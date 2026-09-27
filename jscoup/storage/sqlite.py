# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Local SQLite storage backend.

The file is created next to the application (``.jscoup/jscoup.db`` by
default). Connections are per-thread, WAL is enabled so the dashboard can read
while requests write, and old rows are trimmed by age and by count.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional

from ..dbwatch import raw_connect
from ..security import private_file
from ..models import EventRecord
from .base import BaseStorage

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id                TEXT PRIMARY KEY,
    ts                REAL NOT NULL,
    kind              TEXT,
    name              TEXT,
    status            TEXT,
    severity          TEXT,
    category          TEXT,
    method            TEXT,
    path              TEXT,
    route             TEXT,
    status_code       INTEGER,
    duration_ms       REAL,
    error_type        TEXT,
    error_message     TEXT,
    fingerprint       TEXT,
    culprit           TEXT,
    actor_subject     TEXT,
    actor_label       TEXT,
    token_fingerprint TEXT,
    service           TEXT,
    environment       TEXT,
    trace_id          TEXT,
    simulation_id     TEXT,
    parent_id         TEXT,
    query_count       INTEGER DEFAULT 0,
    db_time_ms        REAL DEFAULT 0,
    resolved          INTEGER DEFAULT 0,
    payload           TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_status ON events(status);
CREATE INDEX IF NOT EXISTS idx_events_category ON events(category);
CREATE INDEX IF NOT EXISTS idx_events_fingerprint ON events(fingerprint);
CREATE INDEX IF NOT EXISTS idx_events_actor ON events(actor_subject);
CREATE INDEX IF NOT EXISTS idx_events_sim ON events(simulation_id);

CREATE TABLE IF NOT EXISTS queries (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id   TEXT NOT NULL,
    seq        INTEGER,
    sql        TEXT,
    params     TEXT,
    duration_ms REAL,
    rowcount   INTEGER,
    error      TEXT,
    backend    TEXT,
    caller     TEXT
);
CREATE INDEX IF NOT EXISTS idx_queries_event ON queries(event_id);
"""


class SQLiteStorage(BaseStorage):
    """Thread-safe local storage for captured events."""

    def __init__(self, db_path: str = ".jscoup/jscoup.db", max_events: int = 5000,
                 retention_days: int = 14):
        self.db_path = os.path.abspath(db_path)
        self.max_events = max_events
        self.retention_days = retention_days
        self._local = threading.local()
        self._write_lock = threading.Lock()
        directory = os.path.dirname(self.db_path)
        if directory:
            os.makedirs(directory, mode=0o700, exist_ok=True)
        private_file(self.db_path)
        self._init_schema()
        self._writes_since_trim = 0

    # -- connection handling ---------------------------------------------- #

    @property
    def conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = raw_connect(self.db_path, timeout=10, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA busy_timeout=5000")
            private_file(self.db_path)
            self._local.conn = conn
        return conn

    def _init_schema(self) -> None:
        with self._write_lock:
            self.conn.executescript(SCHEMA)
            self.conn.commit()

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None

    # -- writes ------------------------------------------------------------ #

    def save(self, event: EventRecord) -> None:
        payload = json.dumps(event.to_dict(), default=str, ensure_ascii=False)
        actor = event.actor
        row = (
            event.id, event.ts, event.kind, event.name, event.status, event.severity,
            event.category, event.method, event.path, event.route, event.status_code,
            event.duration_ms, event.error_type, event.error_message, event.fingerprint,
            event.culprit,
            actor.subject if actor else None,
            actor.label if actor else None,
            actor.token_fingerprint if actor else None,
            event.service, event.environment, event.trace_id, event.simulation_id,
            event.parent_id, event.query_count, event.db_time_ms,
            1 if event.resolved else 0, payload,
        )
        with self._write_lock:
            self.conn.execute(
                """INSERT OR REPLACE INTO events (
                    id, ts, kind, name, status, severity, category, method, path, route,
                    status_code, duration_ms, error_type, error_message, fingerprint, culprit,
                    actor_subject, actor_label, token_fingerprint, service, environment,
                    trace_id, simulation_id, parent_id, query_count, db_time_ms, resolved, payload
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                row,
            )
            # INSERT OR REPLACE only replaces the events row itself, so the
            # old query rows for a re-saved event.id must be cleared first.
            self.conn.execute("DELETE FROM queries WHERE event_id = ?", (event.id,))
            if event.queries:
                self.conn.executemany(
                    """INSERT INTO queries
                       (event_id, seq, sql, params, duration_ms, rowcount, error, backend, caller)
                       VALUES (?,?,?,?,?,?,?,?,?)""",
                    [
                        (event.id, i, q.sql, q.params_preview, q.duration_ms, q.rowcount,
                         q.error, q.backend, q.caller)
                        for i, q in enumerate(event.queries)
                    ],
                )
            self.conn.commit()
            self._writes_since_trim += 1
            if self._writes_since_trim >= 50:
                self._writes_since_trim = 0
                self._trim()

    def _trim(self) -> None:
        if self.retention_days:
            cutoff = time.time() - self.retention_days * 86400
            self.conn.execute("DELETE FROM queries WHERE event_id IN "
                              "(SELECT id FROM events WHERE ts < ?)", (cutoff,))
            self.conn.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
        if self.max_events:
            self.conn.execute(
                """DELETE FROM queries WHERE event_id IN (
                       SELECT id FROM events ORDER BY ts DESC, rowid DESC LIMIT -1 OFFSET ?)""",
                (self.max_events,),
            )
            self.conn.execute(
                "DELETE FROM events WHERE id IN "
                "(SELECT id FROM events ORDER BY ts DESC, rowid DESC LIMIT -1 OFFSET ?)",
                (self.max_events,),
            )
        self.conn.commit()

    def mark_resolved(self, event_id: str, resolved: bool = True) -> bool:
        with self._write_lock:
            cur = self.conn.execute(
                "UPDATE events SET resolved = ? WHERE id = ?", (1 if resolved else 0, event_id)
            )
            self.conn.commit()
        return cur.rowcount > 0

    def purge(self, before: Optional[float] = None) -> int:
        with self._write_lock:
            if before is None:
                count = self.conn.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]
                self.conn.execute("DELETE FROM queries")
                self.conn.execute("DELETE FROM events")
            else:
                count = self.conn.execute(
                    "SELECT COUNT(*) c FROM events WHERE ts < ?", (before,)
                ).fetchone()["c"]
                self.conn.execute(
                    "DELETE FROM queries WHERE event_id IN (SELECT id FROM events WHERE ts < ?)",
                    (before,),
                )
                self.conn.execute("DELETE FROM events WHERE ts < ?", (before,))
            self.conn.commit()
        return int(count)

    # -- reads ------------------------------------------------------------- #

    @staticmethod
    def _where(filters: Dict[str, Any]) -> tuple:
        clauses, params = [], []
        mapping = {
            "status": "status = ?",
            "category": "category = ?",
            "kind": "kind = ?",
            "severity": "severity = ?",
            "fingerprint": "fingerprint = ?",
            "simulation_id": "simulation_id = ?",
        }
        for key, clause in mapping.items():
            value = filters.get(key)
            if value:
                clauses.append(clause)
                params.append(value)
        if filters.get("actor"):
            clauses.append("(actor_subject = ? OR actor_label = ? OR token_fingerprint = ?)")
            params.extend([filters["actor"]] * 3)
        if filters.get("since"):
            clauses.append("ts >= ?")
            params.append(filters["since"])
        if filters.get("search"):
            needle = f"%{filters['search']}%"
            clauses.append(
                "(name LIKE ? OR path LIKE ? OR error_message LIKE ? OR error_type LIKE ?"
                " OR actor_label LIKE ?)"
            )
            params.extend([needle] * 5)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        return where, params

    def list(self, limit: int = 50, offset: int = 0, **filters: Any) -> List[EventRecord]:
        where, params = self._where(filters)
        rows = self.conn.execute(
            f"SELECT payload, resolved FROM events {where} ORDER BY ts DESC, rowid DESC LIMIT ? OFFSET ?",
            (*params, limit, offset),
        ).fetchall()
        return [_hydrate(row) for row in rows]

    def count(self, **filters: Any) -> int:
        where, params = self._where(filters)
        row = self.conn.execute(f"SELECT COUNT(*) c FROM events {where}", params).fetchone()
        return int(row["c"])

    def get(self, event_id: str) -> Optional[EventRecord]:
        row = self.conn.execute(
            "SELECT payload, resolved FROM events WHERE id = ?", (event_id,)
        ).fetchone()
        return _hydrate(row) if row else None

    def issues(self, limit: int = 50, since: Optional[float] = None) -> List[Dict[str, Any]]:
        where, params = self._where({"since": since, "status": "error"})
        rows = self.conn.execute(
            f"""SELECT fingerprint, COUNT(*) AS count, MAX(ts) AS last_seen, MIN(ts) AS first_seen,
                       error_type, error_message, category, severity, name, path, method,
                       COUNT(DISTINCT COALESCE(actor_subject, token_fingerprint)) AS actors,
                       SUM(resolved) AS resolved_count
                FROM events {where}
                GROUP BY fingerprint
                ORDER BY last_seen DESC LIMIT ?""",
            (*params, limit),
        ).fetchall()
        return [dict(row) for row in rows]

    def summary(self, since: Optional[float] = None) -> Dict[str, Any]:
        where, params = self._where({"since": since})
        totals = self.conn.execute(
            f"""SELECT COUNT(*) AS events,
                       SUM(CASE WHEN status='error' THEN 1 ELSE 0 END) AS errors,
                       SUM(CASE WHEN status='slow' THEN 1 ELSE 0 END) AS slow,
                       SUM(CASE WHEN status='ok' THEN 1 ELSE 0 END) AS ok,
                       COUNT(DISTINCT fingerprint) AS issues,
                       COUNT(DISTINCT COALESCE(actor_subject, token_fingerprint)) AS actors,
                       AVG(duration_ms) AS avg_ms,
                       MAX(duration_ms) AS max_ms,
                       SUM(query_count) AS queries
                FROM events {where}""",
            params,
        ).fetchone()
        by_category = self.conn.execute(
            f"""SELECT category, COUNT(*) AS count FROM events {where}
                {'AND' if where else 'WHERE'} status != 'ok'
                GROUP BY category ORDER BY count DESC""",
            params,
        ).fetchall()
        by_endpoint = self.conn.execute(
            f"""SELECT name, COUNT(*) AS count FROM events {where}
                {'AND' if where else 'WHERE'} status = 'error'
                GROUP BY name ORDER BY count DESC LIMIT 8""",
            params,
        ).fetchall()
        by_actor = self.conn.execute(
            f"""SELECT COALESCE(actor_label, 'anonymous') AS actor, COUNT(*) AS count
                FROM events {where}
                {'AND' if where else 'WHERE'} status = 'error'
                GROUP BY actor ORDER BY count DESC LIMIT 8""",
            params,
        ).fetchall()
        data = {k: (totals[k] or 0) for k in totals.keys()}
        data["avg_ms"] = round(float(data.get("avg_ms") or 0), 2)
        data["max_ms"] = round(float(data.get("max_ms") or 0), 2)
        data["by_category"] = [dict(r) for r in by_category]
        data["by_endpoint"] = [dict(r) for r in by_endpoint]
        data["by_actor"] = [dict(r) for r in by_actor]
        return data

    def timeline(self, buckets: int = 60, window_seconds: int = 3600) -> List[Dict[str, Any]]:
        now = time.time()
        start = now - window_seconds
        width = window_seconds / buckets
        rows = self.conn.execute(
            "SELECT ts, status FROM events WHERE ts >= ? ORDER BY ts", (start,)
        ).fetchall()
        series = [
            {"bucket": i, "start": start + i * width, "errors": 0, "slow": 0, "ok": 0}
            for i in range(buckets)
        ]
        for row in rows:
            index = min(int((row["ts"] - start) / width), buckets - 1)
            key = {"error": "errors", "slow": "slow"}.get(row["status"], "ok")
            series[index][key] += 1
        return series


def _hydrate(row: Any) -> EventRecord:
    """Rebuild an event, taking ``resolved`` from the column (it can change)."""
    event = EventRecord.from_dict(json.loads(row["payload"]))
    event.resolved = bool(row["resolved"])
    return event
