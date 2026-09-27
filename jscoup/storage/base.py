# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Storage contract.

Any backend that implements this interface can be plugged into JSCoup
(``JSCoup(storage=MyBackend())``). The bundled SQLite backend keeps everything
on the machine that runs the app — no network calls, no third party service.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..models import EventRecord


class BaseStorage:
    """Persistence interface for captured events."""

    def save(self, event: EventRecord) -> None:
        raise NotImplementedError

    def get(self, event_id: str) -> Optional[EventRecord]:
        raise NotImplementedError

    def list(
        self,
        limit: int = 50,
        offset: int = 0,
        status: Optional[str] = None,
        category: Optional[str] = None,
        kind: Optional[str] = None,
        severity: Optional[str] = None,
        search: Optional[str] = None,
        actor: Optional[str] = None,
        fingerprint: Optional[str] = None,
        since: Optional[float] = None,
        simulation_id: Optional[str] = None,
    ) -> List[EventRecord]:
        raise NotImplementedError

    def count(self, **filters: Any) -> int:
        raise NotImplementedError

    def issues(self, limit: int = 50, since: Optional[float] = None) -> List[Dict[str, Any]]:
        """Events grouped by fingerprint."""
        raise NotImplementedError

    def summary(self, since: Optional[float] = None) -> Dict[str, Any]:
        raise NotImplementedError

    def timeline(self, buckets: int = 60, window_seconds: int = 3600) -> List[Dict[str, Any]]:
        raise NotImplementedError

    def mark_resolved(self, event_id: str, resolved: bool = True) -> bool:
        raise NotImplementedError

    def purge(self, before: Optional[float] = None) -> int:
        raise NotImplementedError

    def close(self) -> None:
        pass
