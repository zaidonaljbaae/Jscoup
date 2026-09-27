# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""In-memory storage — handy for unit tests and ephemeral processes."""

from __future__ import annotations

import threading
import time
from typing import Any, Dict, List, Optional

from ..models import EventRecord
from .base import BaseStorage


class MemoryStorage(BaseStorage):
    def __init__(self, max_events: int = 1000):
        self.max_events = max_events
        self._events: List[EventRecord] = []
        self._lock = threading.Lock()

    def save(self, event: EventRecord) -> None:
        with self._lock:
            self._events.append(event)
            if len(self._events) > self.max_events:
                del self._events[0 : len(self._events) - self.max_events]

    def get(self, event_id: str) -> Optional[EventRecord]:
        return next((e for e in self._events if e.id == event_id), None)

    def _filter(self, **filters: Any) -> List[EventRecord]:
        items = list(reversed(self._events))
        for key in ("status", "category", "kind", "severity", "fingerprint", "simulation_id"):
            value = filters.get(key)
            if value:
                items = [e for e in items if getattr(e, key) == value]
        if filters.get("since"):
            items = [e for e in items if e.ts >= filters["since"]]
        if filters.get("actor"):
            needle = filters["actor"]
            items = [
                e for e in items
                if e.actor and needle in {e.actor.subject, e.actor.label, e.actor.token_fingerprint}
            ]
        if filters.get("search"):
            needle = str(filters["search"]).lower()
            items = [
                e for e in items
                if needle in " ".join(
                    str(x or "") for x in (e.name, e.path, e.error_message, e.error_type)
                ).lower()
            ]
        return items

    def list(self, limit: int = 50, offset: int = 0, **filters: Any) -> List[EventRecord]:
        return self._filter(**filters)[offset : offset + limit]

    def count(self, **filters: Any) -> int:
        return len(self._filter(**filters))

    def issues(self, limit: int = 50, since: Optional[float] = None) -> List[Dict[str, Any]]:
        groups: Dict[str, Dict[str, Any]] = {}
        for event in self._filter(status="error", since=since):
            key = event.fingerprint or event.id
            item = groups.setdefault(
                key,
                {
                    "fingerprint": key, "count": 0, "last_seen": 0, "first_seen": event.ts,
                    "error_type": event.error_type, "error_message": event.error_message,
                    "category": event.category, "severity": event.severity,
                    "name": event.name, "path": event.path, "method": event.method,
                    "actors": 0, "resolved_count": 0,
                },
            )
            item["count"] += 1
            item["last_seen"] = max(item["last_seen"], event.ts)
            item["first_seen"] = min(item["first_seen"], event.ts)
        return sorted(groups.values(), key=lambda i: i["last_seen"], reverse=True)[:limit]

    def summary(self, since: Optional[float] = None) -> Dict[str, Any]:
        items = self._filter(since=since)
        errors = [e for e in items if e.status == "error"]
        categories: Dict[str, int] = {}
        for event in items:
            if event.status != "ok":
                categories[event.category] = categories.get(event.category, 0) + 1
        return {
            "events": len(items),
            "errors": len(errors),
            "slow": len([e for e in items if e.status == "slow"]),
            "ok": len([e for e in items if e.status == "ok"]),
            "issues": len({e.fingerprint for e in errors}),
            "actors": len({e.actor.subject for e in items if e.actor and e.actor.subject}),
            "avg_ms": round(sum(e.duration_ms for e in items) / len(items), 2) if items else 0,
            "max_ms": round(max((e.duration_ms for e in items), default=0), 2),
            "queries": sum(e.query_count for e in items),
            "by_category": [{"category": k, "count": v} for k, v in categories.items()],
            "by_endpoint": [],
            "by_actor": [],
        }

    def timeline(self, buckets: int = 60, window_seconds: int = 3600) -> List[Dict[str, Any]]:
        now = time.time()
        start = now - window_seconds
        width = window_seconds / buckets
        series = [
            {"bucket": i, "start": start + i * width, "errors": 0, "slow": 0, "ok": 0}
            for i in range(buckets)
        ]
        for event in self._events:
            if event.ts < start:
                continue
            index = min(int((event.ts - start) / width), buckets - 1)
            key = {"error": "errors", "slow": "slow"}.get(event.status, "ok")
            series[index][key] += 1
        return series

    def mark_resolved(self, event_id: str, resolved: bool = True) -> bool:
        event = self.get(event_id)
        if event is None:
            return False
        event.resolved = resolved
        return True

    def purge(self, before: Optional[float] = None) -> int:
        with self._lock:
            if before is None:
                count = len(self._events)
                self._events = []
            else:
                keep = [e for e in self._events if e.ts >= before]
                count = len(self._events) - len(keep)
                self._events = keep
        return count
