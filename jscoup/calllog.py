# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""A lightweight record of *every* call JSCoup sees — successes included.

The full event pipeline stores rich, potentially large records (headers,
bodies, SQL, tracebacks) and, unless ``capture_success`` is on, deliberately
drops anything that went fine. This is the cheap counterpart: one small row
per call (which API, what status, how long, who, a truncated response), kept
in its own SQLite file regardless of which storage backend the app's events
use. It answers "which APIs get called, how often, and did they work" for
the Overview and Events views, and is the source of real response examples.

Rows older than ``retention_days`` are deleted (see ``purge_older_than``).
"""

from __future__ import annotations

import os
from .security import private_file
import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS call_log (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    ts               REAL NOT NULL,
    kind             TEXT NOT NULL,
    name             TEXT NOT NULL,
    method           TEXT,
    path             TEXT,
    status_code      INTEGER,
    ok               INTEGER NOT NULL,
    duration_ms      REAL,
    actor            TEXT,
    response_preview TEXT
);
CREATE INDEX IF NOT EXISTS idx_call_log_ts ON call_log(ts DESC);
CREATE INDEX IF NOT EXISTS idx_call_log_name ON call_log(name, ts DESC);
"""

_MAX_PREVIEW = 2000


class CallLogStore:
    def __init__(self, db_path: str = ".jscoup/call_log.db", max_rows: int = 100000):
        self.max_rows = max_rows
        self.db_path = os.path.abspath(db_path)
        directory = os.path.dirname(self.db_path)
        if directory:
            os.makedirs(directory, mode=0o700, exist_ok=True)
        private_file(self.db_path)
        self._local = threading.local()
        self._lock = threading.Lock()
        with self._lock:
            self.conn.executescript(SCHEMA)
            # Remove sensitive legacy columns from the active database. Old
            # backups/free pages require the operator's retention procedure.
            self.conn.execute("UPDATE call_log SET response_preview = NULL, actor = NULL WHERE response_preview IS NOT NULL OR actor IS NOT NULL")
            self.conn.commit()

    @property
    def conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.db_path, timeout=10, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            private_file(self.db_path)
            self._local.conn = conn
        return conn

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None

    def record(
        self,
        *,
        kind: str,
        name: str,
        method: Optional[str],
        path: Optional[str],
        status_code: Optional[int],
        ok: bool,
        duration_ms: Optional[float],
        actor: Optional[str],
        response_preview: Optional[str],
    ) -> None:
        self.record_many([dict(kind=kind, name=name, method=method, path=path,
                               status_code=status_code, ok=ok, duration_ms=duration_ms,
                               actor=actor, response_preview=response_preview)])

    def record_many(self, rows):
        """Commit a bounded batch with one retention check and transaction."""
        values = []
        for row in rows:
            values.append((time.time(), str(row['kind'])[:64], str(row['name'])[:512],
                           str(row['method'])[:16] if row.get('method') else None,
                           str(row['path'])[:512] if row.get('path') else None,
                           row.get('status_code'), 1 if row['ok'] else 0,
                           row.get('duration_ms'), None, None))
        with self._lock:
            try:
                self.conn.executemany(
                    "INSERT INTO call_log (ts, kind, name, method, path, status_code, ok, duration_ms, actor, response_preview) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    values,
                )
                self.conn.execute("DELETE FROM call_log WHERE id <= (SELECT id FROM call_log ORDER BY id DESC LIMIT 1 OFFSET ?)", (self.max_rows,))
                self.conn.commit()
            except BaseException:
                self.conn.rollback()
                raise

    def recent(
        self, limit: int = 100, offset: int = 0, name: Optional[str] = None, ok: Optional[bool] = None,
        since: Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        clauses, args = [], []
        if name:
            clauses.append("name = ?")
            args.append(name)
        if ok is not None:
            clauses.append("ok = ?")
            args.append(1 if ok else 0)
        if since is not None:
            clauses.append("ts >= ?")
            args.append(since)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._lock:
            rows = self.conn.execute(
                f"SELECT * FROM call_log {where} ORDER BY ts DESC LIMIT ? OFFSET ?",
                (*args, limit, offset),
            ).fetchall()
        return [dict(row) for row in rows]

    def count(self, since: Optional[float] = None) -> int:
        with self._lock:
            if since is None:
                row = self.conn.execute("SELECT COUNT(*) AS n FROM call_log").fetchone()
            else:
                row = self.conn.execute("SELECT COUNT(*) AS n FROM call_log WHERE ts >= ?", (since,)).fetchone()
        return int(row["n"])

    def summary(self, since: Optional[float] = None) -> Dict[str, Any]:
        """Per-API totals — every API that was called, with how many of those
        calls succeeded, failed, and how long they took on average."""
        args: tuple = (since,) if since is not None else ()
        where = "WHERE ts >= ?" if since is not None else ""
        with self._lock:
            per_api = self.conn.execute(
                f"SELECT name, kind, method, path, COUNT(*) AS calls, SUM(ok) AS succeeded, "
                f"COUNT(*) - SUM(ok) AS failed, AVG(duration_ms) AS avg_ms, MAX(ts) AS last_ts "
                f"FROM call_log {where} GROUP BY name, kind, method, path ORDER BY calls DESC",
                args,
            ).fetchall()
            totals = self.conn.execute(
                f"SELECT COUNT(*) AS calls, COALESCE(SUM(ok), 0) AS succeeded FROM call_log {where}", args,
            ).fetchone()
        calls = int(totals["calls"])
        succeeded = int(totals["succeeded"])
        return {
            "total_calls": calls,
            "succeeded": succeeded,
            "failed": calls - succeeded,
            "apis": [
                {
                    "name": row["name"], "kind": row["kind"], "method": row["method"], "path": row["path"],
                    "calls": int(row["calls"]), "succeeded": int(row["succeeded"] or 0),
                    "failed": int(row["failed"] or 0),
                    "avg_ms": round(row["avg_ms"], 1) if row["avg_ms"] is not None else None,
                    "last_ts": row["last_ts"],
                }
                for row in per_api
            ],
        }

    def last_response(self, name: str, status_code: int) -> Optional[str]:
        """The most recent stored response body for one API at one exact status."""
        with self._lock:
            row = self.conn.execute(
                "SELECT response_preview FROM call_log WHERE name = ? AND status_code = ? "
                "AND response_preview IS NOT NULL ORDER BY ts DESC LIMIT 1",
                (name, status_code),
            ).fetchone()
        return row["response_preview"] if row else None

    def seen_statuses(self, name: str) -> Dict[int, str]:
        """``{status_code: latest response body}`` for every status this API
        has ever returned (within retention)."""
        with self._lock:
            rows = self.conn.execute(
                "SELECT status_code, response_preview, MAX(ts) FROM call_log "
                "WHERE name = ? AND status_code IS NOT NULL AND response_preview IS NOT NULL "
                "GROUP BY status_code",
                (name,),
            ).fetchall()
        return {int(row["status_code"]): row["response_preview"] for row in rows}

    def purge_older_than(self, cutoff_ts: float) -> int:
        with self._lock:
            cur = self.conn.execute("DELETE FROM call_log WHERE ts < ?", (cutoff_ts,))
            self.conn.commit()
        return cur.rowcount


class CallLogSink:
    """Publisher adapter; closes the writer thread's own SQLite connection."""
    def __init__(self, store, retention_days=30):
        self.retention_days = retention_days
        self.store = store
        self._last_purge = 0
    def save(self, row):
        self.store.record(**row)
        self._purge()
    def save_batch(self, rows):
        self.store.record_many(rows)
        self._purge()
    def _purge(self):
        if time.monotonic() - self._last_purge > 3600:
            self._last_purge = time.monotonic()
            if self.retention_days > 0:
                self.store.purge_older_than(time.time() - self.retention_days * 86400)
    def close(self):
        self.store.close()
