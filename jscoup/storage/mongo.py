# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""MongoDB storage backend — the document-database counterpart to
:class:`~jscoup.storage.sql.SqlStorage`. Every captured
:class:`~jscoup.models.EventRecord` is stored as one document, with no
second table needed for queries/breadcrumbs.

Optional: lazy-imports ``pymongo`` at call time, never at import time, so
JSCoup stays fully usable with zero third-party dependencies when this
backend isn't used. Install with ``pip install jscoup[mongo]``.

Accepts a connection URL, discrete parts, or an SSH tunnel, via the shared
helpers in :mod:`jscoup.storage.connections`.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from ..models import EventRecord
from .base import BaseStorage


class MongoStorage(BaseStorage):
    """Thread-safe storage backed by MongoDB via ``pymongo``."""

    def __init__(
        self,
        url: Optional[str] = None,
        database: str = "jscoup",
        collection: str = "events",
        max_events: Optional[int] = None,
        retention_days: Optional[int] = 14,
        *,
        host: Optional[str] = None,
        port: Optional[int] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        ssh_tunnel: Optional[Dict[str, Any]] = None,
        **client_kwargs: Any,
    ):
        try:
            import pymongo
        except ImportError as exc:
            raise ImportError(
                "MongoStorage needs pymongo — install it with `pip install "
                "jscoup[mongo]` (or `pip install pymongo`)."
            ) from exc

        self._tunnel = None
        if ssh_tunnel and url:
            raise ValueError("For SSH use discrete Mongo connection fields; URI plus tunnel is ambiguous")
        if ssh_tunnel:
            from .connections import apply_ssh_tunnel

            target_host = host or "127.0.0.1"
            target_port = port or 27017
            self._tunnel, host, port = apply_ssh_tunnel(
                ssh_tunnel, target_host=target_host, target_port=target_port
            )
            url = None  # a tunnel always connects by host/port, not the original URL

        try:
            self._pymongo = pymongo
            self.max_events = max_events
            self.retention_days = retention_days
            if url:
                self.client = pymongo.MongoClient(url, **client_kwargs)
            else:
                self.client = pymongo.MongoClient(
                    host=host, port=port, username=username, password=password, **client_kwargs
                )
            self.db = self.client[database]
            self.events = self.db[collection]
            self.events.create_index("ts")
            self.events.create_index("status")
            self.events.create_index("category")
            self.events.create_index("fingerprint")
            self.events.create_index("simulation_id")

        except BaseException:
            resource = getattr(self, "engine", None)
            if resource is None:resource = getattr(self, "client", None)
            if resource is not None:
                if hasattr(resource, "dispose"):resource.dispose()
                else:resource.close()
            if self._tunnel:self._tunnel.stop()
            raise

    @classmethod
    def from_file(cls, path: str, **overrides: Any) -> "MongoStorage":
        """Build a :class:`MongoStorage` from a connection file (``.json``,
        ``.yaml``/``.yml`` or ``.ini``) — see
        :func:`jscoup.storage.connections.load_connection_file`."""
        from .connections import load_connection_file

        data = load_connection_file(path)
        data.update(overrides)
        return cls(**data)

    def close(self) -> None:
        self.client.close()
        if self._tunnel is not None:
            self._tunnel.stop()

    # -- writes ------------------------------------------------------------ #

    def save(self, event: EventRecord) -> None:
        doc = event.to_dict()
        doc["_id"] = event.id
        self.events.replace_one({"_id": event.id}, doc, upsert=True)
        self._writes_since_trim = getattr(self, "_writes_since_trim", 0) + 1
        if self._writes_since_trim >= 50:
            self._writes_since_trim = 0
            self._trim()

    def _trim(self) -> None:
        if self.retention_days:
            cutoff = time.time() - self.retention_days * 86400
            self.events.delete_many({"ts": {"$lt": cutoff}})
        if self.max_events:
            total = self.events.count_documents({})
            overflow = total - self.max_events
            if overflow > 0:
                stale_ids = [
                    d["_id"] for d in
                    self.events.find({}, {"_id": 1}).sort([("ts", 1), ("_id", 1)]).limit(overflow)
                ]
                if stale_ids:
                    self.events.delete_many({"_id": {"$in": stale_ids}})

    def mark_resolved(self, event_id: str, resolved: bool = True) -> bool:
        result = self.events.update_one({"_id": event_id}, {"$set": {"resolved": resolved}})
        return result.matched_count > 0

    def purge(self, before: Optional[float] = None) -> int:
        query = {"ts": {"$lt": before}} if before is not None else {}
        return self.events.delete_many(query).deleted_count

    # -- reads --------------------------------------------------------------- #

    def _query(self, **filters: Any) -> Dict[str, Any]:
        query: Dict[str, Any] = {}
        for key in ("status", "category", "kind", "severity", "fingerprint", "simulation_id"):
            if filters.get(key):
                query[key] = filters[key]
        if filters.get("since"):
            query["ts"] = {"$gte": filters["since"]}
        if filters.get("actor"):
            actor = filters["actor"]
            query["$or"] = [
                {"actor.subject": actor}, {"actor.label": actor}, {"actor.token_fingerprint": actor},
            ]
        if filters.get("search"):
            import re
            needle = re.escape(str(filters["search"]))
            query.setdefault("$and", [])
            query["$and"].append({"$or": [
                {"name": {"$regex": needle, "$options": "i"}},
                {"path": {"$regex": needle, "$options": "i"}},
                {"error_message": {"$regex": needle, "$options": "i"}},
                {"error_type": {"$regex": needle, "$options": "i"}},
            ]})
        return query

    def get(self, event_id: str) -> Optional[EventRecord]:
        doc = self.events.find_one({"_id": event_id})
        return _hydrate(doc) if doc else None

    def list(self, limit: int = 50, offset: int = 0, **filters: Any) -> List[EventRecord]:
        if limit <= 0:
            return []
        if offset < 0:
            raise ValueError("offset must be nonnegative")
        cursor = (
            self.events.find(self._query(**filters))
            .sort([("ts", -1), ("_id", -1)])
            .skip(offset)
            .limit(limit)
        )
        return [_hydrate(doc) for doc in cursor]

    def count(self, **filters: Any) -> int:
        return self.events.count_documents(self._query(**filters))

    def issues(self, limit: int = 50, since: Optional[float] = None) -> List[Dict[str, Any]]:
        if limit <= 0:
            return []
        query = self._query(status="error", since=since)
        pipeline = [
            {"$match": query},
            {"$sort": {"ts": -1, "_id": -1}},
            {"$group": {
                "_id": {"$ifNull": ["$fingerprint", "$_id"]},
                "count": {"$sum": 1},
                "last_seen": {"$max": "$ts"},
                "first_seen": {"$min": "$ts"},
                "error_type": {"$first": "$error_type"},
                "error_message": {"$first": "$error_message"},
                "category": {"$first": "$category"},
                "severity": {"$first": "$severity"},
                "name": {"$first": "$name"},
                "path": {"$first": "$path"},
                "method": {"$first": "$method"},
                "resolved_count": {"$sum": {"$cond": ["$resolved", 1, 0]}},
                "actors": {"$addToSet": {"$ifNull": ["$actor.subject", "$actor.token_fingerprint"]}},
            }},
            {"$sort": {"last_seen": -1}},
            {"$limit": limit},
        ]
        results = []
        for row in self.events.aggregate(pipeline):
            row["fingerprint"] = row.pop("_id")
            row["actors"] = len([a for a in row.get("actors", []) if a])
            results.append(row)
        return results

    def summary(self, since: Optional[float] = None) -> Dict[str, Any]:
        """Server-side aggregation: a single ``$facet`` pipeline computes
        every total and breakdown inside MongoDB itself, so only the small,
        pre-aggregated results cross the wire."""
        query = self._query(since=since)
        pipeline = [
            {"$match": query},
            {"$facet": {
                "totals": [{"$group": {
                    "_id": None,
                    "events": {"$sum": 1},
                    "errors": {"$sum": {"$cond": [{"$eq": ["$status", "error"]}, 1, 0]}},
                    "slow": {"$sum": {"$cond": [{"$eq": ["$status", "slow"]}, 1, 0]}},
                    "ok": {"$sum": {"$cond": [{"$eq": ["$status", "ok"]}, 1, 0]}},
                    "avg_ms": {"$avg": "$duration_ms"},
                    "max_ms": {"$max": "$duration_ms"},
                    "queries": {"$sum": "$query_count"},
                }}],
                "issues": [
                    # Matching {"$type": "string"} rather than "$ne": None,
                    # since fingerprint/actor.subject are always strings when
                    # present, and null-matching semantics for an absent
                    # field diverge across aggregation engines.
                    {"$match": {"status": "error", "fingerprint": {"$type": "string"}}},
                    {"$group": {"_id": "$fingerprint"}},
                    {"$count": "n"},
                ],
                "actors": [
                    {"$match": {"actor.subject": {"$type": "string"}}},
                    {"$group": {"_id": "$actor.subject"}},
                    {"$count": "n"},
                ],
                "by_category": [
                    {"$match": {"status": {"$ne": "ok"}}},
                    {"$group": {"_id": {"$ifNull": ["$category", "none"]}, "count": {"$sum": 1}}},
                    {"$sort": {"count": -1}},
                ],
                "by_endpoint": [
                    {"$match": {"status": "error"}},
                    {"$group": {"_id": {"$ifNull": ["$name", ""]}, "count": {"$sum": 1}}},
                    {"$sort": {"count": -1}},
                    {"$limit": 8},
                ],
                "by_actor": [
                    {"$match": {"status": "error"}},
                    {"$group": {"_id": {"$ifNull": ["$actor.label", "anonymous"]}, "count": {"$sum": 1}}},
                    {"$sort": {"count": -1}},
                    {"$limit": 8},
                ],
            }},
        ]
        result = next(iter(self.events.aggregate(pipeline)), {})
        totals = next(iter(result.get("totals", [])), {})

        def _n(facet_name: str) -> int:
            rows = result.get(facet_name, [])
            return rows[0]["n"] if rows else 0

        return {
            "events": totals.get("events", 0),
            "errors": totals.get("errors", 0),
            "slow": totals.get("slow", 0),
            "ok": totals.get("ok", 0),
            "issues": _n("issues"),
            "actors": _n("actors"),
            "avg_ms": round(totals.get("avg_ms") or 0, 2),
            "max_ms": round(totals.get("max_ms") or 0, 2),
            "queries": totals.get("queries", 0),
            "by_category": [{"category": r["_id"], "count": r["count"]} for r in result.get("by_category", [])],
            "by_endpoint": [{"name": r["_id"], "count": r["count"]} for r in result.get("by_endpoint", [])],
            "by_actor": [{"actor": r["_id"], "count": r["count"]} for r in result.get("by_actor", [])],
        }

    def timeline(self, buckets: int = 60, window_seconds: int = 3600) -> List[Dict[str, Any]]:
        now = time.time()
        start = now - window_seconds
        width = window_seconds / buckets
        series = [
            {"bucket": i, "start": start + i * width, "errors": 0, "slow": 0, "ok": 0}
            for i in range(buckets)
        ]
        for doc in self.events.find({"ts": {"$gte": start}}, {"ts": 1, "status": 1}):
            index = min(int((doc["ts"] - start) / width), buckets - 1)
            key = {"error": "errors", "slow": "slow"}.get(doc.get("status"), "ok")
            series[index][key] += 1
        return series


def _hydrate(doc: Dict[str, Any]) -> EventRecord:
    doc = dict(doc)
    doc.pop("_id", None)
    return EventRecord.from_dict(doc)
