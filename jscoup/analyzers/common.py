# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Analyzers for everything that is not a driver level database error."""

from __future__ import annotations

import re
from typing import Optional

from ..models import Diagnosis, SEVERITY_CRITICAL, SEVERITY_ERROR, SEVERITY_WARNING
from .base import (
    CATEGORY_ACCESS,
    CATEGORY_AUTH,
    CATEGORY_CONFIG,
    CATEGORY_DATA_SHAPE,
    CATEGORY_HTTP,
    CATEGORY_LOGIC,
    CATEGORY_NETWORK,
    CATEGORY_PERFORMANCE,
    CATEGORY_UNKNOWN,
    CATEGORY_VALIDATION,
    AnalysisInput,
    BaseAnalyzer,
)

_NONE_ATTR = re.compile(r"'nonetype' object has no attribute '([\w_]+)'", re.I)
_NONE_SUB = re.compile(r"'nonetype' object is not subscriptable", re.I)
_UNSUPPORTED = re.compile(
    r"unsupported operand type\(s\) for ([^:]+): '([\w.]+)' and '([\w.]+)'", re.I
)
_CONCAT = re.compile(r'can only concatenate (\w+) \(not "([\w.]+)"\) to \1', re.I)
_KEY = re.compile(r"^'?([^']+)'?$")


class DataShapeAnalyzer(BaseAnalyzer):
    """Mismatch between the shape of stored data and what the code assumes.

    This is the most common "it worked on my machine" bug: a NULL column, a
    renamed key, a row tuple that grew a column, a string where a number was
    expected.
    """

    name = "data_shape"
    priority = 20

    def analyze(self, data: AnalysisInput) -> Optional[Diagnosis]:
        message = data.error_message or ""
        lowered = message.lower()
        touched_db = bool(data.queries)
        db_note = (
            "The row was read from the database in this same call, so the value most "
            "likely comes from a NULL column or a changed schema."
            if touched_db
            else "The value came from the request payload or from an upstream call."
        )

        if data.is_instance("KeyError"):
            key = _KEY.sub(r"\1", message.strip())
            return self.verdict(
                category=CATEGORY_DATA_SHAPE,
                subtype="missing_key",
                title=f"Missing key: {key}",
                summary=f"Code read the key {key!r} from a mapping that does not contain it. {db_note}",
                likely_causes=[
                    "The database row / JSON payload uses a different name for this field",
                    "An optional field was assumed to be always present",
                    "A SELECT does not include the column the code later reads",
                ],
                suggested_fixes=[
                    f"Use .get({key!r}) with an explicit default, or validate the payload first",
                    "Select the column explicitly and map rows through a typed structure",
                ],
                evidence={"key": key, "read_from_db": touched_db, "queries": len(data.queries)},
                severity=SEVERITY_ERROR,
                confidence=0.85,
            )

        if data.is_instance("AttributeError") and _NONE_ATTR.search(lowered):
            attr = _NONE_ATTR.search(lowered).group(1)  # type: ignore[union-attr]
            return self._none_verdict(f"attribute .{attr}", db_note, data)

        if data.is_instance("TypeError") and _NONE_SUB.search(lowered):
            return self._none_verdict("an index/key lookup", db_note, data)

        if data.is_instance("TypeError") and "nonetype" in lowered:
            return self._none_verdict("an arithmetic or comparison operation", db_note, data)

        match = _UNSUPPORTED.search(lowered)
        if match and data.is_instance("TypeError"):
            op, left, right = match.groups()
            return self.verdict(
                category=CATEGORY_DATA_SHAPE,
                subtype="type_mismatch",
                title=f"Type mismatch in '{op.strip()}': {left} vs {right}",
                summary=(
                    f"An operation combined a {left} with a {right}. {db_note}"
                ),
                likely_causes=[
                    "A numeric column is stored as TEXT (SQLite is permissive about this)",
                    "A query parameter arrived as a string and was never cast",
                    "A NULL/None default leaked into a calculation",
                ],
                suggested_fixes=[
                    "Cast at the boundary: int()/float()/Decimal() with a clear error on failure",
                    "Add COALESCE(column, 0) in the query, or a NOT NULL default in the schema",
                ],
                evidence={"operator": op.strip(), "left_type": left, "right_type": right},
                severity=SEVERITY_ERROR,
                confidence=0.8,
            )

        concat = _CONCAT.search(lowered)
        if concat and data.is_instance("TypeError"):
            other_type = concat.group(2)
            return self.verdict(
                category=CATEGORY_DATA_SHAPE,
                subtype="str_concat_mismatch",
                title=f"String concatenated with {other_type}",
                summary=(
                    f"Code used '+' to join a string with a {other_type} value. {db_note}"
                ),
                likely_causes=[
                    "A numeric id or column value was concatenated into a message without casting",
                    "A request parameter arrived as the wrong type and was never converted",
                ],
                suggested_fixes=[
                    f"Wrap the {other_type} value in str(...) before concatenating",
                    "Use an f-string or .format() instead of '+' to avoid the cast entirely",
                ],
                evidence={"other_type": other_type},
                severity=SEVERITY_ERROR,
                confidence=0.85,
            )

        if data.is_instance("IndexError") and touched_db:
            return self.verdict(
                category=CATEGORY_DATA_SHAPE,
                subtype="row_shape",
                title="Row unpacked with the wrong number of columns",
                summary="Code indexed a row position that the result set does not have. " + db_note,
                likely_causes=[
                    "SELECT * with positional access after a column was added or removed",
                    "An empty result set treated as if it always had rows",
                ],
                suggested_fixes=[
                    "Select columns explicitly and read them by name (sqlite3.Row / dict cursor)",
                    "Check for an empty result before indexing",
                ],
                evidence={"queries": len(data.queries)},
                severity=SEVERITY_ERROR,
                confidence=0.7,
            )

        if data.is_instance("ValueError") and (
            "invalid literal" in lowered
            or "could not convert" in lowered
            or "does not match format" in lowered
            or "unconverted data" in lowered
            or "isoformat" in lowered
        ):
            return self.verdict(
                category=CATEGORY_VALIDATION,
                subtype="parse_error",
                title="A value could not be parsed",
                summary=f"Conversion failed for a value that did not have the expected format. {db_note}",
                likely_causes=[
                    "Free-form text stored in a column that is parsed as a number or date",
                    "A query string parameter used without validation",
                    "Mixed date formats between writers",
                ],
                suggested_fixes=[
                    "Validate and coerce input with a schema (pydantic, marshmallow, serializers)",
                    "Store dates in ISO-8601 and parse with a single helper",
                    "Return 422 with the offending field instead of raising",
                ],
                evidence={"raw_message": message[:300]},
                severity=SEVERITY_WARNING,
                confidence=0.75,
            )
        return None

    def _none_verdict(self, what: str, db_note: str, data: AnalysisInput) -> Diagnosis:
        return self.verdict(
            category=CATEGORY_DATA_SHAPE,
            subtype="unexpected_none",
            title=f"None used where a value was required ({what})",
            summary=f"The code assumed a value but received None. {db_note}",
            likely_causes=[
                "A nullable column returned NULL for this row",
                "A lookup returned no row and the None result was not checked",
                "An optional request field defaulted to None",
            ],
            suggested_fixes=[
                "Guard the None case explicitly and return a clear 404/422",
                "Use COALESCE in the query or a NOT NULL default in the schema",
                "Model the row with a dataclass/pydantic model that makes nullability visible",
            ],
            evidence={"queries": len(data.queries)},
            severity=SEVERITY_ERROR,
            confidence=0.8,
        )


class ValidationAnalyzer(BaseAnalyzer):
    """Schema / serializer level failures."""

    name = "validation"
    priority = 30

    def analyze(self, data: AnalysisInput) -> Optional[Diagnosis]:
        if not data.is_instance(
            "ValidationError",
            "RequestValidationError",
            "pydantic_core._pydantic_core.ValidationError",
            "MarshmallowValidationError",
            "BadRequest",
            "BadRequestKeyError",
            "UnprocessableEntity",
        ):
            return None
        return self.verdict(
            category=CATEGORY_VALIDATION,
            subtype="payload_rejected",
            title="Request payload failed validation",
            summary="The incoming payload does not match the declared schema.",
            likely_causes=[
                "A client sends an older payload shape than the endpoint expects",
                "A required field is missing or has the wrong type",
                "Content-Type is not application/json so the body never parsed",
            ],
            suggested_fixes=[
                "Return the field level errors to the client with 422 and keep them stable",
                "Version the endpoint if the schema changed in a breaking way",
                "Document the schema and keep the client contract in sync",
            ],
            evidence={"raw_message": (data.error_message or "")[:500]},
            severity=SEVERITY_WARNING,
            confidence=0.85,
        )


class AuthAnalyzer(BaseAnalyzer):
    name = "auth"
    priority = 35

    def analyze(self, data: AnalysisInput) -> Optional[Diagnosis]:
        lowered = data.message_lower
        if data.status_code in (401, 403) or data.is_instance(
            "Unauthorized", "Forbidden", "PermissionDenied", "AuthenticationFailed",
            "InvalidTokenError", "ExpiredSignatureError", "JWTError", "DecodeError",
        ) or "signature" in lowered and "token" in lowered:
            expired = "expired" in lowered
            return self.verdict(
                category=CATEGORY_AUTH,
                subtype="token_expired" if expired else "token_rejected",
                title="Credential rejected" if not expired else "Credential expired",
                summary="The request was refused by authentication or authorization.",
                likely_causes=[
                    "Expired or revoked token" if expired else "Missing, malformed or wrong-audience token",
                    "The client sends the credential in a header the server does not read",
                    "Clock skew between issuer and server",
                ],
                suggested_fixes=[
                    "Answer 401 with WWW-Authenticate and a machine readable reason",
                    "Refresh the token on the client before it expires",
                    "Log the token fingerprint (never the token) to trace the caller",
                ],
                evidence={"status_code": data.status_code},
                severity=SEVERITY_WARNING,
                confidence=0.7,
            )
        return None


class AccessAnalyzer(BaseAnalyzer):
    """Permission / authorization failures, as distinct from authentication.

    Runs before :class:`AuthAnalyzer` (lower ``priority``) so it claims 403
    and OS-level permission errors first, leaving 401 to AuthAnalyzer.
    """

    name = "access"
    priority = 33

    def analyze(self, data: AnalysisInput) -> Optional[Diagnosis]:
        if data.is_instance("PermissionError"):
            return self.verdict(
                category=CATEGORY_ACCESS,
                subtype="permission_denied",
                title="Permission denied accessing a file or resource",
                summary="The process does not have the OS-level permission needed for this operation.",
                likely_causes=[
                    "The file/directory is owned by another user or has restrictive permissions",
                    "The process is running as a user without write access to this path",
                    "A mounted volume or deployment target is read-only",
                ],
                suggested_fixes=[
                    "Check ownership and permissions on the path in the traceback (chmod/chown)",
                    "Run the process as a user that has the access it needs, not by widening permissions ad hoc",
                    "If this is a container/deployment, confirm the volume is writable where expected",
                ],
                evidence={"culprit": data.culprit},
                severity=SEVERITY_ERROR,
                confidence=0.75,
            )
        if data.status_code == 403 or data.is_instance("Forbidden", "PermissionDenied"):
            return self.verdict(
                category=CATEGORY_ACCESS,
                subtype="forbidden",
                title="Request rejected: not authorized",
                summary="The caller was identified but does not have permission to do this.",
                likely_causes=[
                    "The caller's role/scope does not include this action",
                    "A resource-level ownership check failed (acting on someone else's data)",
                    "A permission was recently changed/revoked but the client still has an old token",
                ],
                suggested_fixes=[
                    "Return 403 with the specific permission/scope that was missing",
                    "Double check the role/scope check against the endpoint's actual requirement",
                    "Log the actor and the resource together to spot ownership-check bugs",
                ],
                evidence={"status_code": data.status_code},
                severity=SEVERITY_WARNING,
                confidence=0.7,
            )
        return None


class NetworkAnalyzer(BaseAnalyzer):
    """Outbound calls: upstream APIs, queues, caches."""

    name = "network"
    priority = 40

    def analyze(self, data: AnalysisInput) -> Optional[Diagnosis]:
        lowered = data.message_lower
        if not (
            data.is_instance(
                "ConnectionError", "ConnectTimeout", "ReadTimeout", "Timeout", "TimeoutError",
                "ConnectError", "SSLError", "socket.timeout", "gaierror", "HTTPError",
                "ClientConnectorError", "ServerDisconnectedError", "TooManyRedirects",
                "ConnectionRefusedError", "ConnectionResetError",
            )
            or "max retries exceeded" in lowered
            or "failed to establish a new connection" in lowered
        ):
            return None
        timeout = "timeout" in lowered or "timed out" in lowered
        return self.verdict(
            category=CATEGORY_NETWORK,
            subtype="upstream_timeout" if timeout else "upstream_unreachable",
            title="Upstream call failed" + (" with a timeout" if timeout else ""),
            summary="An outbound network call did not complete.",
            likely_causes=[
                "The upstream service is down, slow or rate limiting",
                "DNS, TLS or firewall problem between the two services",
                "No timeout configured, so the request hung until the client gave up",
            ],
            suggested_fixes=[
                "Set explicit connect and read timeouts on every outbound client",
                "Add retries with jitter for idempotent calls and a circuit breaker for the rest",
                "Degrade gracefully: cached response or 503 with Retry-After",
            ],
            evidence={"raw_message": (data.error_message or "")[:300]},
            severity=SEVERITY_CRITICAL if not timeout else SEVERITY_ERROR,
            confidence=0.8,
        )


class ConfigAnalyzer(BaseAnalyzer):
    name = "config"
    priority = 50

    def analyze(self, data: AnalysisInput) -> Optional[Diagnosis]:
        lowered = data.message_lower
        if data.is_instance("ImportError", "ModuleNotFoundError"):
            subtype, title = "missing_dependency", "A dependency is not installed"
        elif data.is_instance("FileNotFoundError") or "no such file" in lowered:
            subtype, title = "missing_file", "A required file or path is missing"
        elif data.is_instance("KeyError") and "environ" in (data.traceback_text or "").lower():
            subtype, title = "missing_env", "An environment variable is not set"
        else:
            return None
        return self.verdict(
            category=CATEGORY_CONFIG,
            subtype=subtype,
            title=title,
            summary="The process is missing something it needs from its environment.",
            likely_causes=[
                "The environment differs from the developer machine",
                "A package or file is present locally but not in the image/deployment",
            ],
            suggested_fixes=[
                "Validate configuration at startup and fail loudly with the missing name",
                "Pin the dependency in requirements and rebuild the image",
            ],
            evidence={"raw_message": (data.error_message or "")[:300]},
            severity=SEVERITY_CRITICAL,
            confidence=0.75,
        )


class HttpAnalyzer(BaseAnalyzer):
    """Recorded failures that carry an HTTP status but no exception."""

    name = "http"
    priority = 60

    def analyze(self, data: AnalysisInput) -> Optional[Diagnosis]:
        if data.exception is not None or not data.status_code:
            return None
        code = data.status_code
        if code < 400:
            return None
        if 400 <= code < 500:
            return self.verdict(
                category=CATEGORY_HTTP,
                subtype=f"client_error_{code}",
                title=f"Client error {code}",
                summary="The endpoint refused the request without raising an exception.",
                likely_causes=[
                    "The client sends a shape the endpoint no longer accepts",
                    "A route or method mismatch",
                ],
                suggested_fixes=[
                    "Return a body that names the failing field",
                    "Check the client contract and the route definition",
                ],
                evidence={"status_code": code},
                severity=SEVERITY_WARNING,
                confidence=0.5,
            )
        return self.verdict(
            category=CATEGORY_HTTP,
            subtype=f"server_error_{code}",
            title=f"Server error {code}",
            summary="The endpoint returned a server error response.",
            likely_causes=["An error was caught and converted to a 5xx without a traceback"],
            suggested_fixes=["Record the original exception with jscoup.record_exception()"],
            evidence={"status_code": code},
            severity=SEVERITY_ERROR,
            confidence=0.5,
        )


class PerformanceAnalyzer(BaseAnalyzer):
    """Not an exception: slow calls, N+1 query patterns, heavy DB time."""

    name = "performance"
    priority = 70

    def analyze(self, data: AnalysisInput) -> Optional[Diagnosis]:
        if data.exception is not None:
            return None
        signals = data.meta.get("performance") or {}
        n_plus_one = signals.get("n_plus_one")
        slow_ms = signals.get("slow_request_ms")
        if not (n_plus_one or slow_ms):
            return None
        db_ms = round(sum(q.duration_ms for q in data.queries), 2)
        causes, fixes = [], []
        if n_plus_one:
            causes.append(
                f"The same statement shape ran {n_plus_one['count']} times — a classic N+1 loop"
            )
            fixes += [
                "Fetch the related rows in one query (JOIN or WHERE id IN (...))",
                "Batch the loop, or cache the lookup inside the request",
            ]
        if slow_ms:
            causes.append(
                f"The call took {slow_ms} ms of which {db_ms} ms were spent in the database"
            )
            fixes += [
                "Add an index for the filter/sort columns of the slowest statement",
                "Move work that does not affect the response into a background task",
            ]
        return self.verdict(
            category=CATEGORY_PERFORMANCE,
            subtype="n_plus_one" if n_plus_one else "slow_call",
            title="N+1 query pattern detected" if n_plus_one else "Slow call",
            summary="The call succeeded but its database access pattern is expensive.",
            likely_causes=causes,
            suggested_fixes=fixes,
            evidence={
                "duration_ms": data.duration_ms,
                "db_time_ms": db_ms,
                "query_count": len(data.queries),
                "repeated_statement": (n_plus_one or {}).get("sql"),
            },
            severity=SEVERITY_WARNING,
            confidence=0.9,
        )


class GenericAnalyzer(BaseAnalyzer):
    """Last resort so every failure gets at least a usable summary."""

    name = "generic"
    priority = 1000

    def analyze(self, data: AnalysisInput) -> Optional[Diagnosis]:
        category = CATEGORY_LOGIC if data.exception is not None else CATEGORY_UNKNOWN
        hints = []
        if data.is_instance("ZeroDivisionError"):
            hints.append("A denominator was zero — guard empty result sets before dividing")
        if data.is_instance("RecursionError"):
            hints.append("Recursive call without a base case, or a cyclic data structure")
        if data.is_instance("AssertionError"):
            hints.append("An internal invariant does not hold for this input")
        if data.is_instance("NotImplementedError"):
            hints.append("A code path that was never finished is reachable in production")
        return self.verdict(
            category=category,
            subtype="unhandled_exception",
            title=f"Unhandled {data.error_type or 'failure'}",
            summary=(data.error_message or "The call failed without a recognised signature.")[:400],
            likely_causes=hints
            or ["An input reached a code path that does not handle it"],
            suggested_fixes=[
                "Reproduce with the recorded parameters using the live tester in this dashboard",
                "Handle the case explicitly and return a typed error to the client",
            ],
            evidence={"culprit": data.culprit, "queries": len(data.queries)},
            severity=SEVERITY_ERROR,
            confidence=0.3,
        )
