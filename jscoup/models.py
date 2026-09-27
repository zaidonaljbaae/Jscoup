# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Data models used across JSCoup.

Everything that is persisted or rendered in the dashboard is described here.
All dataclasses are JSON serialisable through :func:`to_dict`.
"""

from __future__ import annotations

import hashlib
import re
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

# --------------------------------------------------------------------------- #
# constants
# --------------------------------------------------------------------------- #

SEVERITY_INFO = "info"
SEVERITY_WARNING = "warning"
SEVERITY_ERROR = "error"
SEVERITY_CRITICAL = "critical"

SEVERITY_ORDER = {
    SEVERITY_INFO: 0,
    SEVERITY_WARNING: 1,
    SEVERITY_ERROR: 2,
    SEVERITY_CRITICAL: 3,
}

# Event kinds.
KIND_HTTP = "http"
KIND_SERVICE = "service"
KIND_TASK = "task"
KIND_LAMBDA = "lambda"
KIND_AZURE_FUNCTION = "azure_function"
KIND_OCI_FUNCTION = "oci_function"

STATUS_OK = "ok"
STATUS_ERROR = "error"
STATUS_SLOW = "slow"


def new_id() -> str:
    """Return a short unique identifier."""
    return uuid.uuid4().hex[:24]


# --------------------------------------------------------------------------- #
# records
# --------------------------------------------------------------------------- #


@dataclass
class QueryRecord:
    """A single database statement executed inside a captured operation."""

    sql: str = ""
    params_preview: str = ""
    duration_ms: float = 0.0
    rowcount: Optional[int] = None
    started_at: float = 0.0
    error: Optional[str] = None
    backend: str = "sqlite3"
    caller: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Breadcrumb:
    """A lightweight trace entry recorded before the failure happened."""

    ts: float = field(default_factory=time.time)
    category: str = "note"
    message: str = ""
    data: Dict[str, Any] = field(default_factory=dict)
    level: str = SEVERITY_INFO

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Actor:
    """Who triggered the operation, resolved from the incoming credential."""

    token_fingerprint: Optional[str] = None
    subject: Optional[str] = None
    label: Optional[str] = None
    source: Optional[str] = None  # header name / cookie / query param
    scheme: Optional[str] = None  # bearer / api-key / basic
    claims: Dict[str, Any] = field(default_factory=dict)
    token_preview: Optional[str] = None

    @property
    def is_anonymous(self) -> bool:
        return not (self.subject or self.token_fingerprint)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["is_anonymous"] = self.is_anonymous
        return data


@dataclass
class Diagnosis:
    """The analyzer verdict attached to a failure."""

    category: str = "unknown"
    subtype: str = ""
    title: str = "Unclassified failure"
    summary: str = ""
    likely_causes: List[str] = field(default_factory=list)
    suggested_fixes: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    severity: str = SEVERITY_ERROR
    confidence: float = 0.3
    analyzer: str = "generic"
    docs: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EventRecord:
    """One captured operation: an HTTP request, a service call or a task run."""

    id: str = field(default_factory=new_id)
    ts: float = field(default_factory=time.time)
    kind: str = KIND_HTTP
    name: str = ""
    status: str = STATUS_OK
    severity: str = SEVERITY_INFO
    category: str = "none"

    # http specifics
    method: Optional[str] = None
    path: Optional[str] = None
    route: Optional[str] = None
    query_string: Optional[str] = None
    status_code: Optional[int] = None
    client_ip: Optional[str] = None

    duration_ms: float = 0.0

    # failure specifics
    error_type: Optional[str] = None
    error_module: Optional[str] = None
    error_message: Optional[str] = None
    traceback_text: Optional[str] = None
    fingerprint: Optional[str] = None
    culprit: Optional[str] = None
    culprit_line: Optional[str] = None

    # payloads (already redacted)
    params: Dict[str, Any] = field(default_factory=dict)
    headers: Dict[str, Any] = field(default_factory=dict)
    body_preview: Optional[str] = None
    response_preview: Optional[str] = None
    result_preview: Optional[str] = None
    stdout_capture: Optional[str] = None

    actor: Optional[Actor] = None
    queries: List[QueryRecord] = field(default_factory=list)
    breadcrumbs: List[Breadcrumb] = field(default_factory=list)
    diagnosis: Optional[Diagnosis] = None

    tags: Dict[str, Any] = field(default_factory=dict)
    meta: Dict[str, Any] = field(default_factory=dict)

    parent_id: Optional[str] = None
    trace_id: Optional[str] = None
    simulation_id: Optional[str] = None

    service: str = "service"
    environment: str = "local"
    host: str = ""
    release: Optional[str] = None
    resolved: bool = False

    total_query_count: Optional[int] = None
    total_db_time_ms: Optional[float] = None
    queries_dropped: int = 0

    # ---- derived helpers ------------------------------------------------- #

    @property
    def query_count(self) -> int:
        return self.total_query_count if self.total_query_count is not None else len(self.queries)

    @property
    def db_time_ms(self) -> float:
        return round(self.total_db_time_ms if self.total_db_time_ms is not None else sum(q.duration_ms for q in self.queries), 3)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["query_count"] = self.query_count
        data["db_time_ms"] = self.db_time_ms
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EventRecord":
        data = dict(data)
        data.pop("query_count", None)
        data.pop("db_time_ms", None)
        actor = data.pop("actor", None)
        diagnosis = data.pop("diagnosis", None)
        queries = data.pop("queries", []) or []
        crumbs = data.pop("breadcrumbs", []) or []
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        clean = {k: v for k, v in data.items() if k in known}
        event = cls(**clean)
        if actor:
            actor.pop("is_anonymous", None)
            event.actor = Actor(**actor)
        if diagnosis:
            event.diagnosis = Diagnosis(**diagnosis)
        event.queries = [QueryRecord(**q) for q in queries]
        event.breadcrumbs = [Breadcrumb(**b) for b in crumbs]
        return event


# --------------------------------------------------------------------------- #
# fingerprinting
# --------------------------------------------------------------------------- #

_NUMBERS = re.compile(r"\b\d+\b")
_QUOTED = re.compile(r"""(['"])(?:(?!\1).)*\1""")
_HEX = re.compile(r"\b0x[0-9a-fA-F]+\b")
_UUID = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)


def normalize_message(message: str) -> str:
    """Strip volatile parts of a message so equal failures group together."""
    text = message or ""
    text = _UUID.sub("<uuid>", text)
    text = _HEX.sub("<hex>", text)
    text = _QUOTED.sub("<val>", text)
    text = _NUMBERS.sub("<n>", text)
    return " ".join(text.split()).lower()[:400]


def build_fingerprint(error_type: str, message: str, culprit: str = "") -> str:
    """Stable grouping key for an error."""
    raw = f"{error_type}|{normalize_message(message)}|{culprit}"
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


def normalize_sql(sql: str) -> str:
    """Normalise a statement so repeated shapes (N+1) can be detected."""
    text = _QUOTED.sub("?", sql or "")
    text = _NUMBERS.sub("?", text)
    return " ".join(text.split()).lower()[:500]
