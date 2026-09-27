# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""The ambient, per-request (or per-call) capture context.

A :class:`CaptureContext` collects everything that happens while an operation
runs: SQL statements, breadcrumbs, the resolved actor, extra tags. Contexts are
kept in a stack so a service invoked inside an HTTP request produces its own
event while still contributing its queries to the parent event.
"""

from __future__ import annotations

import time
from contextvars import ContextVar, Token
from typing import Any, Dict, List, Optional

from .models import Actor, Breadcrumb, EventRecord, QueryRecord, new_id

_stack: ContextVar[tuple] = ContextVar("jscoup_stack", default=())


class CaptureContext:
    """Mutable state for one in-flight operation."""

    __slots__ = (
        "id",
        "kind",
        "name",
        "started_at",
        "queries",
        "breadcrumbs",
        "tags",
        "meta",
        "params",
        "headers",
        "actor",
        "parent_id",
        "trace_id",
        "simulation_id",
        "method",
        "path",
        "route",
        "query_string",
        "client_ip",
        "body_preview",
        "status_code",
        "response_preview",
        "result_preview",
        "max_breadcrumbs",
        "max_queries",
        "query_total", "query_duration", "queries_dropped", "capture_query_caller",
        "suppressed",
        "stdout_text",
        "max_stdout_chars",
    )

    def __init__(
        self,
        kind: str,
        name: str,
        parent_id: Optional[str] = None,
        max_breadcrumbs: int = 100,
        max_queries: int = 200,
        max_stdout_chars: int = 4000,
    ):
        self.id = new_id()
        self.kind = kind
        self.name = name
        self.started_at = time.perf_counter()
        self.queries: List[QueryRecord] = []
        self.breadcrumbs: List[Breadcrumb] = []
        self.tags: Dict[str, Any] = {}
        self.meta: Dict[str, Any] = {}
        self.params: Dict[str, Any] = {}
        self.headers: Dict[str, Any] = {}
        self.actor: Optional[Actor] = None
        self.parent_id = parent_id
        self.trace_id: Optional[str] = None
        self.simulation_id: Optional[str] = None
        self.method: Optional[str] = None
        self.path: Optional[str] = None
        self.route: Optional[str] = None
        self.query_string: Optional[str] = None
        self.client_ip: Optional[str] = None
        self.body_preview: Optional[str] = None
        self.status_code: Optional[int] = None
        self.response_preview: Optional[str] = None
        self.result_preview: Optional[str] = None
        self.max_breadcrumbs = max_breadcrumbs
        self.max_queries = max_queries
        self.query_total = 0
        self.query_duration = 0.0
        self.queries_dropped = 0
        self.capture_query_caller = False
        self.suppressed = False
        self.stdout_text = ""
        self.max_stdout_chars = max_stdout_chars

    # -- collectors -------------------------------------------------------- #

    def add_breadcrumb(self, crumb: Breadcrumb) -> None:
        self.breadcrumbs.append(crumb)
        if len(self.breadcrumbs) > self.max_breadcrumbs:
            del self.breadcrumbs[0 : len(self.breadcrumbs) - self.max_breadcrumbs]

    def add_query(self, query: QueryRecord) -> None:
        self.query_total += 1
        self.query_duration += query.duration_ms
        if len(self.queries) >= self.max_queries:
            self.queries_dropped += 1
            if query.error and self.queries:
                self.queries[-1] = query
            return
        self.queries.append(query)

    def set_tag(self, key: str, value: Any) -> None:
        self.tags[str(key)] = value

    def add_stdout(self, text: str) -> None:
        if len(self.stdout_text) >= self.max_stdout_chars:
            return
        self.stdout_text += text
        if len(self.stdout_text) > self.max_stdout_chars:
            self.stdout_text = self.stdout_text[: self.max_stdout_chars] + "…"

    @property
    def elapsed_ms(self) -> float:
        return round((time.perf_counter() - self.started_at) * 1000, 3)

    # -- lifecycle --------------------------------------------------------- #

    def __enter__(self) -> "CaptureContext":
        push(self)
        return self

    def __exit__(self, *exc_info) -> bool:  # pragma: no cover - trivial
        pop(self)
        return False


# --------------------------------------------------------------------------- #
# stack helpers
# --------------------------------------------------------------------------- #


def push(ctx: CaptureContext) -> Token:
    stack = _stack.get()
    return _stack.set(stack + (ctx,))


def pop(ctx: Optional[CaptureContext] = None) -> None:
    stack = _stack.get()
    if not stack:
        return
    if ctx is None or stack[-1] is ctx:
        _stack.set(stack[:-1])
    else:
        _stack.set(tuple(item for item in stack if item is not ctx))


def current_context() -> Optional[CaptureContext]:
    stack = _stack.get()
    return stack[-1] if stack else None


def all_contexts() -> tuple:
    return _stack.get()


def reset() -> None:
    _stack.set(())


def record_query(query: QueryRecord) -> None:
    """Attach a statement to every active context (child and its parents)."""
    for ctx in _stack.get():
        if not ctx.suppressed:
            ctx.add_query(query)


def record_stdout(text: str) -> None:
    """Attach captured print() output to every active context."""
    for ctx in _stack.get():
        ctx.add_stdout(text)


def add_breadcrumb(
    message: str, category: str = "note", level: str = "info", **data: Any
) -> None:
    ctx = current_context()
    if ctx is None:
        return
    ctx.add_breadcrumb(Breadcrumb(category=category, message=message, data=data, level=level))
