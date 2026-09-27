# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Server-side, revocable admin dashboard sessions.

A small local SQLite table holds a hash of each issued token, checked fresh
against the database on every request so every worker process sharing the
file agrees, with an immediate delete-on-logout. This mirrors
``jscoup.gateway.GatewayStore``'s own session design.
"""

from __future__ import annotations

import os
from ..security import private_file
import hashlib
import secrets
import sqlite3
import threading
import time
from typing import Optional

from ..dbwatch import raw_connect
from ..identity import fingerprint_token
from .auth import hash_password, verify_password

SCHEMA = """
CREATE TABLE IF NOT EXISTS dashboard_sessions_v2 (
    token_hash        TEXT PRIMARY KEY,
    token_fingerprint TEXT NOT NULL,
    username          TEXT NOT NULL,
    realm             TEXT NOT NULL,
    issued_at         REAL NOT NULL,
    expires_at        REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_dashboard_sessions_v2_fp ON dashboard_sessions_v2(token_fingerprint);

CREATE TABLE IF NOT EXISTS dashboard_login_attempts (
    realm        TEXT NOT NULL,
    key          TEXT NOT NULL,
    attempts     INTEGER NOT NULL,
    locked_until REAL NOT NULL,
    PRIMARY KEY (realm, key)
);
"""


class SessionStore:
    """Thread-safe local store for admin dashboard login sessions."""

    def __init__(self, db_path: str, realm: str = "default"):
        self.realm = realm
        self.db_path = os.path.abspath(db_path)
        directory = os.path.dirname(self.db_path)
        if directory:
            os.makedirs(directory, mode=0o700, exist_ok=True)
        private_file(self.db_path)
        self._local = threading.local()
        self._lock = threading.Lock()
        with self._lock:
            self.conn.executescript(SCHEMA)
            self.conn.commit()

    @property
    def conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = raw_connect(self.db_path, timeout=10, check_same_thread=False)
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

    def _digest(self, token):
        return "sha256:" + hashlib.sha256((self.realm + "\0" + token).encode()).hexdigest()

    def create(self, username: str, ttl_seconds: float) -> str:
        token = secrets.token_urlsafe(32)
        now = time.time()
        expires_at = now + ttl_seconds
        with self._lock:
            self.conn.execute(
                "INSERT INTO dashboard_sessions_v2 (token_hash, token_fingerprint, username, "
                "issued_at, expires_at, realm) VALUES (?,?,?,?,?,?)",
                (self._digest(token), fingerprint_token(token), username, now, expires_at, self.realm),
            )
            self.conn.execute("DELETE FROM dashboard_sessions_v2 WHERE expires_at < ?", (now,))
            self.conn.commit()
        return token

    def verify(self, token: Optional[str]) -> Optional[str]:
        """Return the username this still-valid session was issued for, or
        ``None`` if missing/unknown/expired. Reads the database fresh on
        every call."""
        if not token:
            return None
        with self._lock:
            row = self.conn.execute(
                "SELECT token_hash, username, expires_at FROM dashboard_sessions_v2 "
                "WHERE token_hash = ?",
                (self._digest(token),),
            ).fetchone()
        if row is None or row["expires_at"] < time.time():
            return None
        return row["username"]

    def revoke(self, token: Optional[str]) -> None:
        """Immediately invalidate one session — called at logout."""
        if not token:
            return
        with self._lock:
            self.conn.execute(
                "DELETE FROM dashboard_sessions_v2 WHERE token_hash = ?",
                (self._digest(token),),
            )
            self.conn.commit()

    def revoke_all(self) -> None:
        """Invalidate every current admin session, e.g. after a password change."""
        with self._lock:
            self.conn.execute("DELETE FROM dashboard_sessions_v2 WHERE realm = ?", (self.realm,))
            self.conn.commit()

    # -- login lockout --------------------------------------------------------- #
    #
    # Shares this same SQLite file rather than an in-memory dict, for the
    # same reason sessions do: several worker processes serve one app, and
    # a per-process counter both fails to lock out a real attacker (each
    # worker gives them a fresh set of attempts) and can lock out a real
    # admin inconsistently (a burst landing on one worker looks locked
    # there but not on another).

    def is_login_locked(self, key: str) -> bool:
        with self._lock:
            row = self.conn.execute(
                "SELECT locked_until FROM dashboard_login_attempts WHERE realm = ? AND key = ?",
                (self.realm, key),
            ).fetchone()
        return row is not None and row["locked_until"] > time.time()

    def record_login_failure(self, key: str, max_attempts: int, lockout_seconds: float) -> None:
        with self._lock:
            row = self.conn.execute(
                "SELECT attempts FROM dashboard_login_attempts WHERE realm = ? AND key = ?",
                (self.realm, key),
            ).fetchone()
            attempts = (row["attempts"] if row else 0) + 1
            locked_until = time.time() + lockout_seconds if attempts >= max_attempts else 0.0
            self.conn.execute(
                "INSERT OR REPLACE INTO dashboard_login_attempts (realm, key, attempts, locked_until) "
                "VALUES (?,?,?,?)",
                (self.realm, key, attempts, locked_until),
            )
            self.conn.commit()

    def clear_login_failures(self, key: str) -> None:
        with self._lock:
            self.conn.execute(
                "DELETE FROM dashboard_login_attempts WHERE realm = ? AND key = ?", (self.realm, key)
            )
            self.conn.commit()

    def allow_rate(self, key, limit, window):
        from ..security import allow_quota
        with self._lock:
            return allow_quota(self.conn, self.realm + ":" + key, limit, window)
