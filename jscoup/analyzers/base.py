# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Analyzer contract.

An analyzer looks at a failure (exception + the context it happened in) and
returns a :class:`~jscoup.models.Diagnosis`, or ``None`` when it has nothing
useful to say. Analyzers are ordered by :attr:`BaseAnalyzer.priority`; the first
non-``None`` verdict wins, which keeps behaviour predictable and easy to extend.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..models import Diagnosis, QueryRecord

CATEGORY_DATABASE = "database"
CATEGORY_DATA_SHAPE = "data_shape"
CATEGORY_VALIDATION = "validation"
CATEGORY_NETWORK = "network"
CATEGORY_AUTH = "auth"
CATEGORY_ACCESS = "access"
CATEGORY_HTTP = "http"
CATEGORY_PERFORMANCE = "performance"
CATEGORY_CONFIG = "config"
CATEGORY_LOGIC = "logic"
CATEGORY_UNKNOWN = "unknown"


@dataclass
class AnalysisInput:
    """Everything an analyzer is allowed to look at."""

    exception: Optional[BaseException] = None
    error_type: str = ""
    error_module: str = ""
    error_message: str = ""
    traceback_text: str = ""
    culprit: str = ""
    culprit_line: str = ""
    kind: str = "http"
    name: str = ""
    status_code: Optional[int] = None
    duration_ms: float = 0.0
    queries: List[QueryRecord] = field(default_factory=list)
    params: Dict[str, Any] = field(default_factory=dict)
    meta: Dict[str, Any] = field(default_factory=dict)

    @property
    def last_query(self) -> Optional[QueryRecord]:
        return self.queries[-1] if self.queries else None

    @property
    def failed_query(self) -> Optional[QueryRecord]:
        for query in reversed(self.queries):
            if query.error:
                return query
        return None

    @property
    def message_lower(self) -> str:
        return (self.error_message or "").lower()

    def is_instance(self, *names: str) -> bool:
        """Match on class name or ``module.ClassName`` without importing drivers."""
        chain = set()
        exc = self.exception
        if exc is not None:
            for klass in type(exc).__mro__:
                chain.add(klass.__name__)
                chain.add(f"{klass.__module__}.{klass.__name__}")
        chain.add(self.error_type)
        chain.add(f"{self.error_module}.{self.error_type}")
        return any(name in chain for name in names)


class BaseAnalyzer:
    """Subclass this to teach JSCoup about a new failure family."""

    name = "base"
    priority = 100

    def analyze(self, data: AnalysisInput) -> Optional[Diagnosis]:  # pragma: no cover
        raise NotImplementedError

    # small helper so subclasses stay short
    def verdict(self, **kwargs: Any) -> Diagnosis:
        kwargs.setdefault("analyzer", self.name)
        return Diagnosis(**kwargs)
