# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Database failure analysis.

This analyzer is driver agnostic: it recognises sqlite3, psycopg/psycopg2,
MySQL, asyncpg, SQLAlchemy and the Django DB wrappers by exception name and by
the wording of the driver message, so no database package has to be installed.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

from ..models import Diagnosis, SEVERITY_CRITICAL, SEVERITY_ERROR, SEVERITY_WARNING
from .base import CATEGORY_DATABASE, AnalysisInput, BaseAnalyzer

# Exception class names that always mean "the database layer failed."
DB_EXCEPTION_NAMES = {
    "OperationalError",
    "IntegrityError",
    "ProgrammingError",
    "DataError",
    "InternalError",
    "InterfaceError",
    "DatabaseError",
    "NotSupportedError",
    "DBAPIError",
    "StatementError",
    "InvalidRequestError",
    "PendingRollbackError",
    "PoolError",
    "DisconnectionError",
    "UniqueViolation",
    "ForeignKeyViolation",
    "NotNullViolation",
    "CheckViolation",
    "UndefinedTable",
    "UndefinedColumn",
    "DeadlockDetected",
    "SerializationFailure",
    "TooManyConnections",
    "ObjectDoesNotExist",
    "DoesNotExist",
    "MultipleObjectsReturned",
}

# Names that are also a plain Python/stdlib exception (or common in an
# unrelated library), so a bare class-name match alone isn't reliable;
# SQLAlchemy's own TimeoutError for a pool checkout shares its name with the
# built-in TimeoutError raised for ordinary network/queue timeouts. Requires
# the module to also look like a DB driver, or an already-failed query.
AMBIGUOUS_DB_EXCEPTION_NAMES = {"TimeoutError"}

# Exact driver exception class name -> the specific rule it always means,
# checked before any text-pattern matching, since a structured signal this
# specific should never lose to a vaguer text pattern (e.g. UndefinedColumn
# vs. the broader "missing_table" pattern, both matching "does not exist").
EXCEPTION_NAME_TO_SUBTYPE = {
    "UndefinedColumn": "missing_column",
    "UndefinedTable": "missing_table",
    "UniqueViolation": "unique_violation",
    "ForeignKeyViolation": "foreign_key_violation",
    "NotNullViolation": "not_null_violation",
    "CheckViolation": "check_violation",
    "DeadlockDetected": "locked",
    "SerializationFailure": "locked",
    "TooManyConnections": "pool_exhausted",
    "DoesNotExist": "not_found",
    "ObjectDoesNotExist": "not_found",
    "MultipleObjectsReturned": "not_found",
}

DB_MODULE_HINTS = (
    "sqlite3",
    "psycopg",
    "psycopg2",
    "pymysql",
    "mysql",
    "asyncpg",
    "sqlalchemy",
    "django.db",
    "aiosqlite",
    "oracledb",
    "pyodbc",
)

_TABLE_RE = re.compile(r"(?:no such table|relation|table)\s*[:\"']?\s*([\w.\"]+)", re.I)
_COLUMN_RE = re.compile(r"(?:no such column|column)\s*[:\"']?\s*([\w.\"]+)", re.I)
_CONSTRAINT_RE = re.compile(r"constraint failed:\s*([\w.]+)", re.I)


class Rule:
    """One recognisable database problem."""

    __slots__ = ("subtype", "patterns", "title", "summary", "causes", "fixes", "severity")

    def __init__(
        self,
        subtype: str,
        patterns: Tuple[str, ...],
        title: str,
        summary: str,
        causes: List[str],
        fixes: List[str],
        severity: str = SEVERITY_ERROR,
    ):
        self.subtype = subtype
        self.patterns = patterns
        self.title = title
        self.summary = summary
        self.causes = causes
        self.fixes = fixes
        self.severity = severity


RULES: Tuple[Rule, ...] = (
    Rule(
        "unique_violation",
        ("unique constraint failed", "duplicate key value", "duplicate entry", "unique violation",
         "unique index"),
        "Duplicate value rejected by a unique constraint",
        "The row being written already exists for a column that must stay unique.",
        [
            "The client retried a create request and the first attempt already succeeded",
            "The uniqueness check runs in application code and races with a concurrent insert",
            "A natural key (email, slug, external id) is reused across tenants",
        ],
        [
            "Check for an existing row inside the same transaction, or use an upsert "
            "(INSERT ... ON CONFLICT / INSERT OR REPLACE)",
            "Return 409 Conflict with the conflicting field instead of a 500",
            "Make the request idempotent with an idempotency key",
        ],
    ),
    Rule(
        "foreign_key_violation",
        ("foreign key constraint failed", "violates foreign key constraint",
         "a foreign key constraint fails", "foreign key violation"),
        "Foreign key points at a row that does not exist",
        "The write references a parent row that is missing, or a parent is being deleted "
        "while children still reference it.",
        [
            "The referenced id came from the client and was never validated",
            "The parent row was deleted (or never committed) before the child insert",
            "Delete without ON DELETE CASCADE / SET NULL on the child table",
        ],
        [
            "Validate the referenced id exists before writing and answer 422 when it does not",
            "Wrap parent and child writes in a single transaction",
            "Declare the intended ON DELETE behaviour on the constraint",
        ],
    ),
    Rule(
        "not_null_violation",
        ("not null constraint failed", "violates not-null constraint", "cannot be null",
         "not null violation"),
        "Required column received NULL",
        "A column declared NOT NULL was written without a value.",
        [
            "An optional request field is inserted directly without a default",
            "A schema migration added a NOT NULL column while old code still writes the old shape",
            "A computed value silently returned None",
        ],
        [
            "Give the column a server side DEFAULT or make it nullable",
            "Validate the payload before the insert and return 422 with the missing field",
            "Keep write code and migrations in the same deploy",
        ],
    ),
    Rule(
        "check_violation",
        ("check constraint failed", "violates check constraint"),
        "Value rejected by a CHECK constraint",
        "The value written is outside the range the schema allows.",
        ["Business rules enforced only in the database", "Unvalidated numeric or enum input"],
        ["Mirror the constraint in request validation", "Return 422 with the offending field"],
    ),
    Rule(
        "missing_table",
        ("no such table", "undefined table", "does not exist", "doesn't exist",
         "relation does not exist"),
        "Schema drift: the table is missing",
        "The statement targets a table that is not present in the connected database.",
        [
            "Migrations were not applied on this environment",
            "The process is connected to the wrong database file or schema",
            "The table name is misspelled or was renamed by a migration",
        ],
        [
            "Run the migrations for this environment and verify the connection string",
            "Log the resolved database path/DSN at startup",
            "Add a startup check that asserts the expected tables exist",
        ],
        SEVERITY_CRITICAL,
    ),
    Rule(
        "missing_column",
        ("no such column", "undefined column", "unknown column", "column does not exist"),
        "Schema drift: the column is missing",
        "The statement selects or writes a column the connected schema does not have.",
        [
            "Code deployed ahead of its migration",
            "A rolled back migration left the schema behind",
            "A typo or an alias that is never defined",
        ],
        [
            "Apply the pending migration, or guard the new field behind a feature flag",
            "Use expand/contract migrations so old and new code both work",
        ],
        SEVERITY_CRITICAL,
    ),
    Rule(
        "locked",
        ("database is locked", "database table is locked", "lock wait timeout",
         "deadlock detected", "deadlock found", "could not obtain lock"),
        "Lock contention on the database",
        "Another transaction is holding a lock this statement needs.",
        [
            "A long running write transaction blocks readers (typical with SQLite)",
            "Two transactions take locks in a different order",
            "A connection was left open without commit or rollback",
        ],
        [
            "Keep transactions short and commit as soon as the write is done",
            "For SQLite enable WAL mode and set a busy timeout",
            "Always take locks in the same order, and retry with backoff on deadlock",
        ],
        SEVERITY_CRITICAL,
    ),
    Rule(
        "pool_exhausted",
        ("queuepool limit", "too many connections", "timeout expired", "pool timeout",
         "connection pool is full", "remaining connection slots"),
        "Connection pool exhausted",
        "Every pooled connection is checked out, so this call waited and gave up.",
        [
            "Connections are not returned (missing close / context manager)",
            "Slow queries hold connections for too long",
            "Pool size too small for the current concurrency",
        ],
        [
            "Always use a context manager or explicit close for sessions and connections",
            "Profile the slowest statements and add the missing indexes",
            "Tune pool_size / max_overflow and add a checkout timeout alarm",
        ],
        SEVERITY_CRITICAL,
    ),
    Rule(
        "connection_failed",
        ("could not connect", "connection refused", "server closed the connection",
         "connection reset", "connection is closed", "can't connect to", "no route to host",
         "name or service not known", "unable to open database file", "connection timed out",
         "terminating connection", "ssl connection has been closed"),
        "The database is unreachable",
        "The driver could not open or keep a connection to the database server.",
        [
            "The database is down, restarting, or failing over",
            "Wrong host/port/credentials for this environment, or the file path does not exist",
            "A network policy, firewall or container network blocks the connection",
        ],
        [
            "Verify the DSN, credentials and network reachability from this host",
            "Add connection retries with backoff and a health check on the pool",
            "Fail fast with 503 instead of holding the request until it times out",
        ],
        SEVERITY_CRITICAL,
    ),
    Rule(
        "type_mismatch",
        ("datatype mismatch", "invalid input syntax", "incorrect integer value",
         "invalid literal", "could not convert", "data type mismatch", "out of range",
         "value too long", "string data, right truncation"),
        "The value does not match the column type",
        "The driver refused a value because its type or size does not fit the column.",
        [
            "Request input is passed to the query without casting",
            "A column type changed but the write path still sends the old type",
            "Numeric overflow or a string longer than the column allows",
        ],
        [
            "Coerce and validate types at the edge (schema/serializer) rather than at the driver",
            "Widen the column, or truncate/round explicitly before writing",
        ],
    ),
    Rule(
        "syntax_error",
        ("syntax error", "near \"", "incomplete input", "you have an error in your sql"),
        "Malformed SQL statement",
        "The database could not parse the statement.",
        [
            "String concatenation built an invalid statement",
            "A placeholder or identifier is quoted incorrectly for this dialect",
        ],
        [
            "Use parameter binding instead of string formatting",
            "Log the exact statement and run it against the same dialect",
        ],
    ),
    Rule(
        "parameter_mismatch",
        ("incorrect number of bindings", "you did not supply a value", "parameters supplied",
         "the sql contains", "too many sql variables", "bind message supplies"),
        "Statement placeholders do not match the parameters",
        "The number or naming of bound parameters does not match the statement.",
        [
            "A parameter was added to the SQL but not to the tuple/dict",
            "Mixing qmark and named placeholder styles",
            "A very large IN (...) list exceeds the driver's variable limit",
        ],
        [
            "Bind parameters as a dict with named placeholders to keep them aligned",
            "Chunk large IN lists, or write to a temporary table and join",
        ],
    ),
    Rule(
        "transaction_state",
        ("pendingrollbackerror", "current transaction is aborted", "transaction has been rolled back",
         "cannot operate on a closed transaction", "no active transaction",
         "cannot start a transaction within a transaction"),
        "The session is in a broken transaction state",
        "A previous statement failed and the transaction was never rolled back.",
        [
            "An exception was swallowed without rollback and the session kept being reused",
            "Nested transactions started on the same connection",
        ],
        [
            "Roll back on every failure path, ideally with a request scoped session context manager",
            "Use SAVEPOINT (begin_nested) for inner transactions",
        ],
    ),
    Rule(
        "readonly",
        ("attempt to write a readonly database", "read-only transaction", "permission denied for table",
         "access denied for user"),
        "Insufficient privileges for the write",
        "The connected user (or file) is not allowed to perform this operation.",
        [
            "File permissions on the SQLite database or its directory",
            "The credential is a read-only replica user",
        ],
        [
            "Fix filesystem ownership, or point writes at the primary",
            "Grant the required privileges to the application role",
        ],
        SEVERITY_CRITICAL,
    ),
    Rule(
        "not_found",
        ("does not exist.", "matching query does not exist", "no row was found",
         "multipleobjectsreturned"),
        "Expected row was not returned",
        "A lookup expected exactly one row and did not get it.",
        [
            "The id came from the client and no longer exists",
            "A filter is wider or narrower than intended",
        ],
        [
            "Return 404 for a missing row instead of letting the exception escape",
            "Use a first()/get_or_none() style helper where absence is legitimate",
        ],
        SEVERITY_WARNING,
    ),
)

RULES_BY_SUBTYPE: Dict[str, Rule] = {rule.subtype: rule for rule in RULES}


class DatabaseAnalyzer(BaseAnalyzer):
    name = "database"
    priority = 10

    def analyze(self, data: AnalysisInput) -> Optional[Diagnosis]:
        if not self._is_database_failure(data):
            return None

        message = data.message_lower
        # Structured evidence (the exact driver exception class) outranks a text pattern.
        rule = RULES_BY_SUBTYPE.get(EXCEPTION_NAME_TO_SUBTYPE.get(data.error_type, ""))
        if rule is None:
            rule = self._match_rule(message)
        evidence = self._evidence(data)

        if rule is None:
            return self.verdict(
                category=CATEGORY_DATABASE,
                subtype="database_error",
                title=f"Database error: {data.error_type}",
                summary="The database driver raised an error that JSCoup could not classify further.",
                likely_causes=[
                    "Driver level failure — read the raw message and the failing statement below",
                ],
                suggested_fixes=[
                    "Run the failing statement manually against the same database",
                    "Add a rule to DatabaseAnalyzer so this message is classified next time",
                ],
                evidence=evidence,
                severity=SEVERITY_ERROR,
                confidence=0.45,
            )

        return self.verdict(
            category=CATEGORY_DATABASE,
            subtype=rule.subtype,
            title=rule.title,
            summary=rule.summary,
            likely_causes=list(rule.causes),
            suggested_fixes=list(rule.fixes),
            evidence=evidence,
            severity=rule.severity,
            confidence=0.9,
        )

    # -- helpers ----------------------------------------------------------- #

    @staticmethod
    def _is_database_failure(data: AnalysisInput) -> bool:
        module = (data.error_module or "").lower()
        module_looks_like_db = any(hint in module for hint in DB_MODULE_HINTS)
        if data.error_type in DB_EXCEPTION_NAMES:
            return True
        if data.error_type in AMBIGUOUS_DB_EXCEPTION_NAMES:
            return module_looks_like_db or data.failed_query is not None
        if module_looks_like_db:
            return True
        if data.exception is not None:
            for klass in type(data.exception).__mro__:
                klass_module = klass.__module__.lower()
                if klass.__name__ in DB_EXCEPTION_NAMES:
                    return True
                if klass.__name__ in AMBIGUOUS_DB_EXCEPTION_NAMES:
                    if any(hint in klass_module for hint in DB_MODULE_HINTS):
                        return True
                    continue
                if any(hint in klass_module for hint in DB_MODULE_HINTS):
                    return True
        # a statement that failed right before the exception is strong evidence
        return data.failed_query is not None

    @staticmethod
    def _match_rule(message: str) -> Optional[Rule]:
        for rule in RULES:
            for pattern in rule.patterns:
                if pattern in message:
                    return rule
        return None

    @staticmethod
    def _evidence(data: AnalysisInput) -> Dict[str, object]:
        query = data.failed_query or data.last_query
        evidence: Dict[str, object] = {
            "driver": data.error_module or "unknown",
            "exception": data.error_type,
            "statements_before_failure": len(data.queries),
        }
        if query is not None:
            evidence["sql"] = query.sql
            evidence["sql_params"] = query.params_preview
            evidence["sql_duration_ms"] = query.duration_ms
            evidence["sql_caller"] = query.caller
        table = _TABLE_RE.search(data.error_message or "")
        if table:
            evidence["table"] = table.group(1).strip('"')
        column = _COLUMN_RE.search(data.error_message or "")
        if column:
            evidence["column"] = column.group(1).strip('"')
        constraint = _CONSTRAINT_RE.search(data.error_message or "")
        if constraint:
            evidence["constraint"] = constraint.group(1)
        return evidence
