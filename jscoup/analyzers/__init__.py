# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Analyzer registry and engine."""

from __future__ import annotations

from typing import Iterable, List, Optional

from ..models import Diagnosis
from .base import (
    CATEGORY_ACCESS,
    CATEGORY_AUTH,
    CATEGORY_CONFIG,
    CATEGORY_DATABASE,
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
from .common import (
    AccessAnalyzer,
    AuthAnalyzer,
    ConfigAnalyzer,
    DataShapeAnalyzer,
    GenericAnalyzer,
    HttpAnalyzer,
    NetworkAnalyzer,
    PerformanceAnalyzer,
    ValidationAnalyzer,
)
from .database import DatabaseAnalyzer

__all__ = [
    "AnalysisInput",
    "BaseAnalyzer",
    "AnalyzerEngine",
    "DatabaseAnalyzer",
    "DataShapeAnalyzer",
    "ValidationAnalyzer",
    "AuthAnalyzer",
    "AccessAnalyzer",
    "NetworkAnalyzer",
    "ConfigAnalyzer",
    "HttpAnalyzer",
    "PerformanceAnalyzer",
    "GenericAnalyzer",
    "default_analyzers",
    "CATEGORY_DATABASE",
    "CATEGORY_DATA_SHAPE",
    "CATEGORY_VALIDATION",
    "CATEGORY_NETWORK",
    "CATEGORY_AUTH",
    "CATEGORY_ACCESS",
    "CATEGORY_HTTP",
    "CATEGORY_PERFORMANCE",
    "CATEGORY_CONFIG",
    "CATEGORY_LOGIC",
    "CATEGORY_UNKNOWN",
]


def default_analyzers() -> List[BaseAnalyzer]:
    return [
        DatabaseAnalyzer(),
        DataShapeAnalyzer(),
        ValidationAnalyzer(),
        AuthAnalyzer(),
        AccessAnalyzer(),
        NetworkAnalyzer(),
        ConfigAnalyzer(),
        HttpAnalyzer(),
        PerformanceAnalyzer(),
        GenericAnalyzer(),
    ]


class AnalyzerEngine:
    """Runs analyzers in priority order and returns the first verdict."""

    def __init__(self, analyzers: Optional[Iterable[BaseAnalyzer]] = None):
        self.analyzers: List[BaseAnalyzer] = list(
            analyzers if analyzers is not None else default_analyzers()
        )
        self._sort()

    def _sort(self) -> None:
        self.analyzers.sort(key=lambda a: a.priority)

    def register(self, analyzer: BaseAnalyzer, replace: bool = False) -> None:
        """Add a custom analyzer. Use a low ``priority`` to run it first."""
        if replace:
            self.analyzers = [a for a in self.analyzers if a.name != analyzer.name]
        self.analyzers.append(analyzer)
        self._sort()

    def unregister(self, name: str) -> None:
        self.analyzers = [a for a in self.analyzers if a.name != name]

    def analyze(self, data: AnalysisInput) -> Optional[Diagnosis]:
        for analyzer in self.analyzers:
            try:
                verdict = analyzer.analyze(data)
            except Exception:  # an analyzer must never break the host app
                continue
            if verdict is not None:
                if data.culprit_line and "source_line" not in verdict.evidence:
                    verdict.evidence["source_line"] = data.culprit_line
                return verdict
        return None
