# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Database instrumentation.

Every statement that runs inside a captured operation is recorded with its
duration, its parameters and the application frame that issued it. That trail is
what turns "IntegrityError" into "this INSERT, with these values, from this
line".

Two integration styles are provided:

* :func:`connect` / :func:`instrument_sqlite3` for the stdlib ``sqlite3`` driver
* :func:`instrument_sqlalchemy` for any SQLAlchemy engine (optional dependency)
"""

from __future__ import annotations

import os
import sqlite3
import sys
import time
import traceback
import weakref
from typing import Any, Iterable, Optional

from .config import DEFAULT_SENSITIVE_KEYS
from .context import all_contexts, record_query
from .models import QueryRecord
from .sanitizer import sql_shape
from .redaction import Redactor

_PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
_MAX_PARAM_CHARS = 300
# Traces every connection process-wide rather than for one JSCoup instance,
# so it has no access to a particular instance's configured sensitive_keys
# and falls back to the library defaults.
_redactor = Redactor(DEFAULT_SENSITIVE_KEYS)


def _caller() -> Optional[str]:
    """First stack frame that belongs to the application, not to JSCoup."""
    for frame in reversed(traceback.extract_stack()[:-2]):
        directory = os.path.dirname(os.path.abspath(frame.filename))
        if directory.startswith(_PACKAGE_DIR):
            continue
        if f"{os.sep}sqlite3{os.sep}" in frame.filename:
            continue
        return f"{os.path.basename(frame.filename)}:{frame.lineno} in {frame.name}"
    return None


def _preview_params(params: Any) -> str:
    if isinstance(params, dict):
        # Named parameters carry key names, so scrub by key first.
        text = repr(_redactor.scrub(params))
    else:
        try:
            text = repr(params)
        except Exception:
            text = "<unrepresentable>"
        text = _redactor.scrub_text(text, limit=_MAX_PARAM_CHARS * 10)
    return text[:_MAX_PARAM_CHARS]


def emit_query(
    sql: str,
    params: Any = None,
    duration_ms: float = 0.0,
    rowcount: Optional[int] = None,
    error: Optional[str] = None,
    backend: str = "sqlite3",
) -> None:
    """Public hook: report a statement from any driver JSCoup does not wrap."""
    if not any(not c.suppressed for c in all_contexts()):
        # Nothing is watching right now; skip the stack walk and repr() work.
        return
    record_query(
        QueryRecord(
            # A literal secret can end up in the SQL text itself (e.g. a
            # query built by string interpolation) or in a driver's error
            # text, not just in the parameters, so both get scrubbed too.
            sql=sql_shape(_redactor.scrub_text((sql or "").strip(), limit=4000)),
            params_preview="[redacted]" if params is not None else None,
            duration_ms=round(duration_ms, 3),
            rowcount=rowcount,
            started_at=time.time(),
            error=_redactor.scrub_text(error) if error else error,
            backend=backend,
            caller=_caller() if any(c.capture_query_caller for c in all_contexts()) else None,
        )
    )


# --------------------------------------------------------------------------- #
# sqlite3
# --------------------------------------------------------------------------- #


class TracedCursor(sqlite3.Cursor):
    """``sqlite3.Cursor`` that reports every statement to the active context."""

    def execute(self, sql: str, parameters: Iterable[Any] = ()):  # type: ignore[override]
        return self._traced(super().execute, sql, parameters)

    def executemany(self, sql: str, seq_of_parameters: Iterable[Any]):  # type: ignore[override]
        return self._traced(super().executemany, sql, seq_of_parameters, many=True)

    def executescript(self, sql_script: str):  # type: ignore[override]
        return self._traced(lambda s, _p: super(TracedCursor, self).executescript(s), sql_script, None)

    def _traced(self, func, sql, params, many: bool = False):
        started = time.perf_counter()
        error = None
        try:
            result = func(sql, params) if params is not None else func(sql, None)
            return result
        except Exception as exc:  # noqa: BLE001 - re-raised below
            error = f"{type(exc).__name__}: {exc}"
            raise
        finally:
            duration = (time.perf_counter() - started) * 1000
            emit_query(
                sql=sql,
                params=params if not many else f"<{_safe_len(params)} rows>",
                duration_ms=duration,
                rowcount=getattr(self, "rowcount", None),
                error=error,
            )


def _safe_len(value: Any) -> str:
    # len(), not len(list(value)): executemany() is often handed a
    # generator, and materialising it here would consume it.
    try:
        return str(len(value))
    except TypeError:
        return "?"


class TracedConnection(sqlite3.Connection):
    """``sqlite3.Connection`` whose cursors are traced by default."""

    def cursor(self, factory=TracedCursor):  # type: ignore[override]
        return super().cursor(factory)

    def execute(self, sql: str, parameters: Iterable[Any] = ()):  # type: ignore[override]
        cur = self.cursor()
        return cur.execute(sql, parameters)

    def executemany(self, sql: str, seq_of_parameters: Iterable[Any]):  # type: ignore[override]
        cur = self.cursor()
        return cur.executemany(sql, seq_of_parameters)

    def executescript(self, sql_script: str):  # type: ignore[override]
        cur = self.cursor()
        return cur.executescript(sql_script)


def connect(database: str, **kwargs: Any) -> sqlite3.Connection:
    """Drop-in replacement for :func:`sqlite3.connect` with tracing enabled."""
    kwargs.setdefault("factory", TracedConnection)
    return sqlite3.connect(database, **kwargs)


_original_connect = None


def instrument_sqlite3() -> None:
    """Patch ``sqlite3.connect`` globally so every connection is traced."""
    global _original_connect
    if _original_connect is not None:
        return
    _original_connect = sqlite3.connect

    def patched(*args: Any, **kwargs: Any):
        if "factory" not in kwargs:
            kwargs["factory"] = TracedConnection
        return _original_connect(*args, **kwargs)  # type: ignore[misc]

    sqlite3.connect = patched  # type: ignore[assignment]


def uninstrument_sqlite3() -> None:
    global _original_connect
    if _original_connect is not None:
        sqlite3.connect = _original_connect  # type: ignore[assignment]
        _original_connect = None


def raw_connect(database: str, **kwargs: Any) -> sqlite3.Connection:
    """Untraced connection — used by JSCoup' own storage to avoid recursion."""
    kwargs["factory"] = sqlite3.Connection
    connect_func = _original_connect or sqlite3.connect
    return connect_func(database, **kwargs)  # type: ignore[misc]


# --------------------------------------------------------------------------- #
# SQLAlchemy (optional)
# --------------------------------------------------------------------------- #

# engine -> (before, after, on_error) listener closures currently attached.
# A WeakKeyDictionary so a disposed engine doesn't leak an entry here, and so
# a repeated instrument_sqlalchemy(engine) call is a no-op instead of
# doubling every recorded query.
_sqlalchemy_listeners: "weakref.WeakKeyDictionary" = weakref.WeakKeyDictionary()


def instrument_sqlalchemy(engine: Any) -> None:
    """Attach JSCoup listeners to a SQLAlchemy ``Engine``. Safe to call more
    than once on the same engine — only the first call actually attaches
    anything.

    Import is done lazily so SQLAlchemy stays an optional dependency.
    """
    if engine in _sqlalchemy_listeners:
        return
    from sqlalchemy import event  # type: ignore

    def before(conn, cursor, statement, parameters, context, executemany):
        conn.info["_jscoup_start"] = time.perf_counter()

    def after(conn, cursor, statement, parameters, context, executemany):
        started = conn.info.pop("_jscoup_start", None)
        duration = (time.perf_counter() - started) * 1000 if started else 0.0
        emit_query(
            sql=statement,
            params=parameters,
            duration_ms=duration,
            rowcount=getattr(cursor, "rowcount", None),
            backend="sqlalchemy",
        )

    def on_error(context):
        statement = getattr(context, "statement", "") or ""
        exc = context.original_exception
        emit_query(
            sql=statement,
            params=getattr(context, "parameters", None),
            duration_ms=0.0,
            error=f"{type(exc).__name__}: {exc}",
            backend="sqlalchemy",
        )

    event.listen(engine, "before_cursor_execute", before)
    event.listen(engine, "after_cursor_execute", after)
    event.listen(engine, "handle_error", on_error)
    _sqlalchemy_listeners[engine] = (before, after, on_error)


def uninstrument_sqlalchemy(engine: Any) -> None:
    """Reverse :func:`instrument_sqlalchemy` — a no-op if it was never
    instrumented (or already uninstrumented)."""
    listeners = _sqlalchemy_listeners.pop(engine, None)
    if listeners is None:
        return
    from sqlalchemy import event  # type: ignore

    before, after, on_error = listeners
    event.remove(engine, "before_cursor_execute", before)
    event.remove(engine, "after_cursor_execute", after)
    event.remove(engine, "handle_error", on_error)


def instrument_django() -> None:
    """Install a Django database instrumentation wrapper on every connection."""
    from django.db import connections  # type: ignore

    def wrapper(execute, sql, params, many, context):
        started = time.perf_counter()
        error = None
        try:
            return execute(sql, params, many, context)
        except Exception as exc:  # noqa: BLE001
            error = f"{type(exc).__name__}: {exc}"
            raise
        finally:
            emit_query(
                sql=sql,
                params=params,
                duration_ms=(time.perf_counter() - started) * 1000,
                error=error,
                backend="django",
            )

    wrapper._is_jscoup_wrapper = True  # type: ignore[attr-defined]
    for alias in connections:
        existing = connections[alias].execute_wrappers
        if any(getattr(w, "_is_jscoup_wrapper", False) for w in existing):
            continue  # already instrumented for this alias
        existing.append(wrapper)
