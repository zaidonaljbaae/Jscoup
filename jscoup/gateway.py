# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""API Gateway: admin-curated per-user access to the discovered API surface.

The admin creates a sub-user with a username, a password, an explicit set of
APIs they're allowed to call, and optionally an IP whitelist (exact IPs or
CIDR ranges, e.g. ``10.0.0.0/8``). The sub-user logs in at ``POST /gw/login``
to obtain a short-lived token (1 hour by default). JSCoup then proxies the
call on that user's behalf via :class:`~jscoup.simulator.Simulator`, rather
than the caller ever reaching the real route directly. Some targets can
instead be marked public: reachable with no token at all.

Always its own small local SQLite file (``.jscoup/gateway.db``), independent
of whichever backend the event storage itself uses.
"""

from __future__ import annotations

import json
import os
from .security import private_file
import re
import secrets
import hashlib
import sqlite3
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, List, Optional, Sequence, Union

from .dashboard.auth import hash_password, ip_allowed, verify_password
from .dbwatch import raw_connect
from .identity import fingerprint_token
from .models import new_id

SCHEMA = """
CREATE TABLE IF NOT EXISTS gateway_users (
    id                 TEXT PRIMARY KEY,
    label              TEXT NOT NULL,
    username           TEXT NOT NULL,
    password_hash      TEXT NOT NULL,
    allowed_target_ids TEXT NOT NULL,
    allowed_ips        TEXT,
    downstream_token   TEXT,
    created_at         REAL NOT NULL,
    revoked            INTEGER NOT NULL DEFAULT 0,
    categories         TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_gateway_users_username ON gateway_users(username);

CREATE TABLE IF NOT EXISTS gateway_sessions (
    token_hash        TEXT PRIMARY KEY,
    token_fingerprint TEXT NOT NULL,
    user_id           TEXT NOT NULL,
    issued_at         REAL NOT NULL,
    expires_at        REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_gateway_sessions_fp ON gateway_sessions(token_fingerprint);

CREATE TABLE IF NOT EXISTS gateway_public_targets (
    target_id TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS gateway_calls (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     TEXT,
    target_id   TEXT NOT NULL,
    ok          INTEGER NOT NULL,
    status_code INTEGER,
    ts          REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_gateway_calls_user ON gateway_calls(user_id, ts DESC);

CREATE TABLE IF NOT EXISTS gateway_manual_targets (
    id          TEXT PRIMARY KEY,
    method      TEXT NOT NULL,
    path        TEXT NOT NULL,
    name        TEXT NOT NULL,
    description TEXT,
    created_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS gateway_disabled_targets (
    target_id TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS gateway_login_attempts (
    key          TEXT PRIMARY KEY,
    attempts     INTEGER NOT NULL,
    locked_until REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS gateway_target_descriptions (
    target_id   TEXT PRIMARY KEY,
    description TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS gateway_doc_groups (
    slug        TEXT PRIMARY KEY,
    title       TEXT NOT NULL,
    target_ids  TEXT NOT NULL,
    allowed_ips TEXT,
    categories  TEXT,
    created_at  REAL NOT NULL
);
"""

ALL_TARGETS = "*"
DEFAULT_TOKEN_TTL_HOURS = 1.0
# Slugs become a URL path segment sitting directly under the dashboard mount
# (e.g. /__jscoup/partners), alongside the reserved "api" and "gw" segments —
# both are rejected so a group can never shadow the admin API or the gateway
# proxy surface.
_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
RESERVED_DOC_GROUP_SLUGS = {"api", "gw"}


@dataclass
class GatewayUser:
    id: str
    label: str
    username: str
    allowed_target_ids: Union[List[str], str]  # a list, or the literal "*" for every target
    created_at: float
    allowed_ips: Optional[List[str]] = None  # None/[] = unrestricted, else exact IPs/CIDRs
    revoked: bool = False
    password_hash: str = field(default="", repr=False)
    # The credential this user's proxied calls carry to the actual API, if
    # it requires its own auth; None for APIs that need none.
    downstream_token: Optional[str] = field(default=None, repr=False)
    # Per-API category this user sees on their docs/tester (target id -> name).
    categories: Dict[str, str] = field(default_factory=dict)

    def allows(self, target_id: str) -> bool:
        if self.revoked:
            return False
        return self.allowed_target_ids == ALL_TARGETS or target_id in self.allowed_target_ids

    def allows_ip(self, client_ip: Optional[str]) -> bool:
        return ip_allowed(client_ip, self.allowed_ips)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "username": self.username,
            "allowed_target_ids": self.allowed_target_ids,
            "allowed_ips": self.allowed_ips,
            "created_at": self.created_at,
            "revoked": self.revoked,
            "categories": self.categories or {},
        }


class GatewayStore:
    """Thread-safe local store for gateway users, their login sessions, and
    public-target flags.

    Every read a security decision depends on (``authenticate``, ``is_public``,
    the user row behind ``login``/``allows``/``allows_ip``) queries the
    database directly on every call rather than an in-memory cache, so
    multiple ``GatewayStore`` instances sharing one database file (e.g.
    multiple worker processes) stay consistent with each other.
    """

    def __init__(self, db_path: str = ".jscoup/gateway.db", token_ttl_hours: float = DEFAULT_TOKEN_TTL_HOURS, realm: str = "", encryption_key=None):
        from .security import realm_path
        self.encryption_key = encryption_key
        if realm:
            db_path = realm_path(db_path, realm)
        self.db_path = os.path.abspath(db_path)
        self.token_ttl_hours = token_ttl_hours
        directory = os.path.dirname(self.db_path)
        if directory:
            os.makedirs(directory, mode=0o700, exist_ok=True)
        private_file(self.db_path)
        self._local = threading.local()
        self._lock = threading.Lock()
        with self._lock:
            self.conn.executescript(SCHEMA)
            self.conn.commit()
            # A database created before "categories" existed has the table
            # without it — CREATE TABLE IF NOT EXISTS above is a no-op there.
            self._ensure_column("gateway_doc_groups", "categories", "TEXT")
            self._ensure_column("gateway_users", "categories", "TEXT")

    def _encrypt_credential(self, value):
        if not value:
            return None
        if not self.encryption_key:
            raise ValueError("Storing downstream credentials requires encryption_key and jscoup[crypto]")
        from .crypto import encrypt_text
        return encrypt_text(value, self.encryption_key)

    def _decrypt_credential(self, value):
        if not value:
            return None
        if not self.encryption_key or not value.startswith("enc:"):
            raise ValueError("Unencrypted legacy downstream credential; recreate the user with encryption enabled")
        from .crypto import decrypt_text
        return decrypt_text(value, self.encryption_key)

    def allow_rate(self, key, limit, window):
        from .security import allow_quota
        with self._lock:
            return allow_quota(self.conn, key, limit, window)

    def _ensure_column(self, table: str, column: str, column_type: str) -> None:
        existing = {row["name"] for row in self.conn.execute(f"PRAGMA table_info({table})").fetchall()}
        if column not in existing:
            self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {column_type}")
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

    def _user_from_row(self, row: Any) -> GatewayUser:
        allowed = row["allowed_target_ids"]
        return GatewayUser(
            id=row["id"], label=row["label"], username=row["username"],
            allowed_target_ids=ALL_TARGETS if allowed == ALL_TARGETS else json.loads(allowed),
            allowed_ips=json.loads(row["allowed_ips"]) if row["allowed_ips"] else None,
            created_at=row["created_at"], revoked=bool(row["revoked"]),
            password_hash=row["password_hash"], downstream_token=self._decrypt_credential(row["downstream_token"]),
            categories=json.loads(row["categories"]) if row["categories"] else {},
        )

    # -- users ---------------------------------------------------------------- #

    def create_user(
        self,
        label: str,
        username: str,
        password: str,
        allowed_target_ids: Union[Sequence[str], str],
        allowed_ips: Optional[Sequence[str]] = None,
        downstream_token: Optional[str] = None,
        categories: Optional[Dict[str, str]] = None,
    ) -> GatewayUser:
        """Define a sub-user's credentials and permissions — no token is
        returned here. The sub-user logs in themselves via
        :meth:`login`/``POST /gw/login`` to obtain one."""
        allowed: Union[List[str], str] = (
            ALL_TARGETS if allowed_target_ids == ALL_TARGETS else list(allowed_target_ids)
        )
        ip_list = list(allowed_ips) if allowed_ips else None
        user = GatewayUser(
            id=new_id(), label=label, username=username, allowed_target_ids=allowed,
            allowed_ips=ip_list, created_at=time.time(),
            password_hash=hash_password(password), downstream_token=downstream_token,
            categories=dict(categories or {}),
        )
        with self._lock:
            self.conn.execute(
                "INSERT INTO gateway_users (id, label, username, password_hash, allowed_target_ids, "
                "allowed_ips, downstream_token, created_at, revoked, categories) VALUES (?,?,?,?,?,?,?,?,0,?)",
                (user.id, user.label, user.username, user.password_hash,
                 allowed if allowed == ALL_TARGETS else json.dumps(allowed),
                 json.dumps(ip_list) if ip_list else None, self._encrypt_credential(downstream_token), user.created_at,
                 json.dumps(user.categories) if user.categories else None),
            )
            self.conn.commit()
        return user

    def list_users(self) -> List[GatewayUser]:
        with self._lock:
            rows = self.conn.execute("SELECT * FROM gateway_users ORDER BY created_at DESC").fetchall()
        return [self._user_from_row(r) for r in rows]

    def revoke(self, user_id: str) -> bool:
        """Marks the user revoked; every session they hold stops
        authenticating immediately, with no need to delete each token."""
        with self._lock:
            cur = self.conn.execute("UPDATE gateway_users SET revoked = 1 WHERE id = ?", (user_id,))
            self.conn.commit()
        return cur.rowcount > 0

    def restore(self, user_id: str) -> bool:
        with self._lock:
            cur = self.conn.execute("UPDATE gateway_users SET revoked = 0 WHERE id = ?", (user_id,))
            self.conn.commit()
        return cur.rowcount > 0

    def reset_password(self, user_id: str, new_password: str) -> bool:
        """Sets a new password and invalidates every session the user
        currently holds, the same way a real password reset should."""
        with self._lock:
            cur = self.conn.execute(
                "UPDATE gateway_users SET password_hash = ? WHERE id = ?",
                (hash_password(new_password), user_id),
            )
            self.conn.execute("DELETE FROM gateway_sessions WHERE user_id = ?", (user_id,))
            self.conn.commit()
        return cur.rowcount > 0

    def update_permissions(
        self,
        user_id: str,
        allowed_target_ids: Optional[Union[Sequence[str], str]] = None,
        allowed_ips: Optional[Sequence[str]] = None,
        categories: Optional[Dict[str, str]] = None,
    ) -> bool:
        """Replace a user's allowed APIs and/or IP allow-list. Pass ``None``
        for a field to leave it unchanged; pass an empty list for
        ``allowed_ips`` to lift the IP restriction entirely."""
        with self._lock:
            if allowed_target_ids is not None:
                allowed: Union[List[str], str] = (
                    ALL_TARGETS if allowed_target_ids == ALL_TARGETS else list(allowed_target_ids)
                )
                self.conn.execute(
                    "UPDATE gateway_users SET allowed_target_ids = ? WHERE id = ?",
                    (allowed if allowed == ALL_TARGETS else json.dumps(allowed), user_id),
                )
            if allowed_ips is not None:
                ip_list = list(allowed_ips) or None
                self.conn.execute(
                    "UPDATE gateway_users SET allowed_ips = ? WHERE id = ?",
                    (json.dumps(ip_list) if ip_list else None, user_id),
                )
            if categories is not None:
                self.conn.execute(
                    "UPDATE gateway_users SET categories = ? WHERE id = ?",
                    (json.dumps(dict(categories)) if categories else None, user_id),
                )
            cur = self.conn.execute("SELECT 1 FROM gateway_users WHERE id = ?", (user_id,))
            found = cur.fetchone() is not None
            self.conn.commit()
        return found

    def delete_user(self, user_id: str) -> bool:
        """Permanently removes the user, its sessions and its call log —
        distinct from :meth:`revoke`, which keeps the row but disables it."""
        with self._lock:
            cur = self.conn.execute("DELETE FROM gateway_users WHERE id = ?", (user_id,))
            self.conn.execute("DELETE FROM gateway_sessions WHERE user_id = ?", (user_id,))
            self.conn.execute("DELETE FROM gateway_calls WHERE user_id = ?", (user_id,))
            self.conn.commit()
        return cur.rowcount > 0

    # -- login / sessions -------------------------------------------------------- #

    def login(self, username: str, password: str, client_ip: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Verify credentials (and, if the user has an IP whitelist, the
        caller's address) and issue a new session token, valid for
        ``token_ttl_hours`` (1 hour by default, so a superadmin-issued token needs reissuing hourly). Returns ``None`` on any
        failure — caller decides what status code that becomes."""
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM gateway_users WHERE username = ?", (username,)
            ).fetchone()
        user = self._user_from_row(row) if row is not None else None
        from .dashboard.auth import dummy_password_hash
        valid = verify_password(password, user.password_hash if user else dummy_password_hash())
        if user is None or user.revoked or not valid:
            return None
        if not user.allows_ip(client_ip):
            return None

        token = secrets.token_urlsafe(32)
        now = time.time()
        expires_at = now + self.token_ttl_hours * 3600
        with self._lock:
            self.conn.execute(
                "INSERT INTO gateway_sessions (token_hash, token_fingerprint, user_id, issued_at, "
                "expires_at) VALUES (?,?,?,?,?)",
                ("sha256:" + hashlib.sha256(token.encode()).hexdigest(), fingerprint_token(token), user.id, now, expires_at),
            )
            self.conn.execute("DELETE FROM gateway_sessions WHERE expires_at < ?", (now,))
            self.conn.commit()
        return {"token": token, "expires_at": expires_at, "user": user}

    def authenticate(self, token: Optional[str]) -> Optional[GatewayUser]:
        """Verified lookup of a still-valid session, reading the session and
        its owning user fresh from the database on every call."""
        if not token:
            return None
        fp = fingerprint_token(token)
        with self._lock:
            session_row = self.conn.execute(
                "SELECT token_hash, user_id, expires_at FROM gateway_sessions WHERE token_hash = ?",
                ("sha256:" + hashlib.sha256(token.encode()).hexdigest(),),
            ).fetchone()
        if session_row is None or session_row["expires_at"] < time.time():
            return None
        with self._lock:
            user_row = self.conn.execute(
                "SELECT * FROM gateway_users WHERE id = ?", (session_row["user_id"],)
            ).fetchone()
        if user_row is None:
            return None
        user = self._user_from_row(user_row)
        if user.revoked:
            return None
        return user

    # -- public targets --------------------------------------------------------- #

    def is_public(self, target_id: str) -> bool:
        with self._lock:
            row = self.conn.execute(
                "SELECT 1 FROM gateway_public_targets WHERE target_id = ?", (target_id,)
            ).fetchone()
        return row is not None

    def set_public(self, target_id: str, public: bool) -> None:
        with self._lock:
            if public:
                self.conn.execute(
                    "INSERT OR IGNORE INTO gateway_public_targets (target_id) VALUES (?)", (target_id,)
                )
            else:
                self.conn.execute(
                    "DELETE FROM gateway_public_targets WHERE target_id = ?", (target_id,)
                )
            self.conn.commit()

    def list_public_targets(self) -> List[str]:
        """Every target id currently marked public — what the public docs
        page (see dashboard/api.py's ``_gateway_docs*``) lists to an
        anonymous visitor."""
        with self._lock:
            rows = self.conn.execute("SELECT target_id FROM gateway_public_targets").fetchall()
        return [row["target_id"] for row in rows]

    # -- admin-curated API descriptions ------------------------------------------ #
    # Separate from Registry.describe()'s in-memory overrides, for the same
    # reason manual targets and disabled targets live here too: written from
    # the dashboard at runtime, by any worker process, so every other worker
    # picks it up on its next refresh_targets() call.

    def set_target_description(self, target_id: str, description: str) -> None:
        with self._lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO gateway_target_descriptions (target_id, description) VALUES (?, ?)",
                (target_id, description),
            )
            self.conn.commit()

    def get_target_descriptions(self) -> Dict[str, str]:
        with self._lock:
            rows = self.conn.execute("SELECT target_id, description FROM gateway_target_descriptions").fetchall()
        return {row["target_id"]: row["description"] for row in rows}

    # -- public doc groups -------------------------------------------------------- #
    # A named, admin-curated subset of the catalogue published at its own URL
    # (mount_path + "/" + slug), reachable with no login at all — gated only
    # by its own allowed_ips (None/empty = open to everyone, i.e. "0.0.0.0").
    # Independent of the removed single docs page, which controlled the single
    # global "every public target" page instead.

    @staticmethod
    def _row_to_doc_group(row: Any) -> Dict[str, Any]:
        return {
            "slug": row["slug"],
            "title": row["title"],
            "target_ids": json.loads(row["target_ids"]),
            "allowed_ips": json.loads(row["allowed_ips"]) if row["allowed_ips"] else None,
            # target_id -> the category it's filed under *in this group*,
            # overriding the docs page's own tag/path-prefix default — lets
            # the same API sit in "billing" on one public page and "internal"
            # on another, since that's a per-group presentation choice.
            "categories": json.loads(row["categories"]) if row["categories"] else {},
            "created_at": row["created_at"],
        }

    def create_doc_group(
        self,
        slug: str,
        title: str,
        target_ids: Sequence[str],
        allowed_ips: Optional[Sequence[str]] = None,
        categories: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        slug = str(slug).strip().lower()
        if not _SLUG_RE.match(slug) or slug in RESERVED_DOC_GROUP_SLUGS:
            raise ValueError(
                "Slug must be lowercase letters, digits or hyphens, and not \"api\" or \"gw\""
            )
        with self._lock:
            try:
                self.conn.execute(
                    "INSERT INTO gateway_doc_groups (slug, title, target_ids, allowed_ips, categories, created_at) "
                    "VALUES (?,?,?,?,?,?)",
                    (
                        slug, title, json.dumps(list(target_ids)),
                        json.dumps(list(allowed_ips)) if allowed_ips else None,
                        json.dumps(categories) if categories else None,
                        time.time(),
                    ),
                )
                self.conn.commit()
            except sqlite3.IntegrityError:
                raise ValueError(f"A group with slug {slug!r} already exists") from None
        group = self.get_doc_group(slug)
        assert group is not None
        return group

    def update_doc_group(
        self,
        slug: str,
        title: Optional[str] = None,
        target_ids: Optional[Sequence[str]] = None,
        allowed_ips: Optional[Sequence[str]] = None,
        categories: Optional[Dict[str, str]] = None,
    ) -> bool:
        """Replace fields on an existing group. Pass ``None`` for a field to
        leave it unchanged; pass an empty list/dict for ``allowed_ips`` /
        ``categories`` to clear it (unrestricted, or back to the default
        category rule for every target)."""
        slug = str(slug).strip().lower()
        with self._lock:
            changed = False
            if title is not None:
                cur = self.conn.execute("UPDATE gateway_doc_groups SET title = ? WHERE slug = ?", (title, slug))
                changed = changed or cur.rowcount > 0
            if target_ids is not None:
                cur = self.conn.execute(
                    "UPDATE gateway_doc_groups SET target_ids = ? WHERE slug = ?",
                    (json.dumps(list(target_ids)), slug),
                )
                changed = changed or cur.rowcount > 0
            if allowed_ips is not None:
                ip_list = list(allowed_ips) or None
                cur = self.conn.execute(
                    "UPDATE gateway_doc_groups SET allowed_ips = ? WHERE slug = ?",
                    (json.dumps(ip_list) if ip_list else None, slug),
                )
                changed = changed or cur.rowcount > 0
            if categories is not None:
                cur = self.conn.execute(
                    "UPDATE gateway_doc_groups SET categories = ? WHERE slug = ?",
                    (json.dumps(categories) if categories else None, slug),
                )
                changed = changed or cur.rowcount > 0
            if title is None and target_ids is None and allowed_ips is None and categories is None:
                exists = self.conn.execute(
                    "SELECT 1 FROM gateway_doc_groups WHERE slug = ?", (slug,)
                ).fetchone()
                changed = exists is not None
            self.conn.commit()
        return changed

    def get_doc_group(self, slug: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM gateway_doc_groups WHERE slug = ?", (str(slug).strip().lower(),)
            ).fetchone()
        return self._row_to_doc_group(row) if row else None

    def list_doc_groups(self) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute("SELECT * FROM gateway_doc_groups ORDER BY created_at").fetchall()
        return [self._row_to_doc_group(row) for row in rows]

    def delete_doc_group(self, slug: str) -> bool:
        with self._lock:
            cur = self.conn.execute("DELETE FROM gateway_doc_groups WHERE slug = ?", (str(slug).strip().lower(),))
            self.conn.commit()
        return cur.rowcount > 0

    # -- per-user call log ------------------------------------------------------ #

    def log_call(self, user_id: Optional[str], target_id: str, ok: bool, status_code: Optional[int]) -> None:
        """Record one proxied call, independent of the main event capture
        pipeline."""
        with self._lock:
            self.conn.execute(
                "INSERT INTO gateway_calls (user_id, target_id, ok, status_code, ts) VALUES (?,?,?,?,?)",
                (user_id, target_id, 1 if ok else 0, status_code, time.time()),
            )
            self.conn.commit()

    # -- manually catalogued targets & disabled targets -------------------------- #
    #
    # Stored here, not on Registry, for the same reason gateway users are:
    # a real deployment runs several worker processes, each with its own
    # in-memory Registry, and an admin action taken against one of them
    # (add a manual API, hide one from the catalogue) has to be visible to
    # every other worker's next request too. JSCoup.refresh_targets() reads
    # both of these on every dashboard request and applies them to that
    # process's own Registry, the same way it already re-applies real route
    # discovery on every request.

    def add_manual_target(
        self, method: str, path: str, name: Optional[str] = None, description: str = ""
    ) -> Dict[str, Any]:
        method = method.upper()
        target_id = f"http:{method}:{path}"
        name = name or f"{method} {path}"
        with self._lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO gateway_manual_targets "
                "(id, method, path, name, description, created_at) VALUES (?,?,?,?,?,?)",
                (target_id, method, path, name, description, time.time()),
            )
            self.conn.commit()
        return {"id": target_id, "method": method, "path": path, "name": name, "description": description}

    def list_manual_targets(self) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT id, method, path, name, description FROM gateway_manual_targets ORDER BY created_at DESC"
            ).fetchall()
        return [dict(row) for row in rows]

    def remove_manual_target(self, target_id: str) -> bool:
        with self._lock:
            cur = self.conn.execute("DELETE FROM gateway_manual_targets WHERE id = ?", (target_id,))
            self.conn.commit()
        return cur.rowcount > 0

    def set_target_disabled(self, target_id: str, disabled: bool) -> None:
        with self._lock:
            if disabled:
                self.conn.execute(
                    "INSERT OR IGNORE INTO gateway_disabled_targets (target_id) VALUES (?)", (target_id,)
                )
            else:
                self.conn.execute("DELETE FROM gateway_disabled_targets WHERE target_id = ?", (target_id,))
            self.conn.commit()

    def disabled_target_ids(self) -> List[str]:
        with self._lock:
            rows = self.conn.execute("SELECT target_id FROM gateway_disabled_targets").fetchall()
        return [row["target_id"] for row in rows]

    # -- login lockout --------------------------------------------------------- #
    # Same reasoning as SessionStore's — shared across worker processes via
    # this store's own database file, not an in-memory-per-process dict.

    def is_login_locked(self, key: str) -> bool:
        with self._lock:
            row = self.conn.execute(
                "SELECT locked_until FROM gateway_login_attempts WHERE key = ?", (key,)
            ).fetchone()
        return row is not None and row["locked_until"] > time.time()

    def record_login_failure(self, key: str, max_attempts: int, lockout_seconds: float) -> None:
        with self._lock:
            row = self.conn.execute(
                "SELECT attempts FROM gateway_login_attempts WHERE key = ?", (key,)
            ).fetchone()
            attempts = (row["attempts"] if row else 0) + 1
            locked_until = time.time() + lockout_seconds if attempts >= max_attempts else 0.0
            self.conn.execute(
                "INSERT OR REPLACE INTO gateway_login_attempts (key, attempts, locked_until) VALUES (?,?,?)",
                (key, attempts, locked_until),
            )
            self.conn.commit()

    def clear_login_failures(self, key: str) -> None:
        with self._lock:
            self.conn.execute("DELETE FROM gateway_login_attempts WHERE key = ?", (key,))
            self.conn.commit()

    def list_calls(self, user_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT target_id, ok, status_code, ts FROM gateway_calls "
                "WHERE user_id = ? ORDER BY ts DESC LIMIT ?",
                (user_id, limit),
            ).fetchall()
        return [dict(row) for row in rows]


class RateLimiter:
    """A small per-key sliding-window request cap, stdlib only.

    Protects the gateway's proxy surface from being hammered or used to
    brute-force targets, using an in-memory deque of recent timestamps per
    key, trimmed on each check.
    """

    def __init__(self, max_requests: int = 120, window_seconds: float = 60.0):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._hits: Dict[str, Deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.time()
        with self._lock:
            hits = self._hits.setdefault(key, deque())
            while hits and now - hits[0] > self.window_seconds:
                hits.popleft()
            if len(hits) >= self.max_requests:
                return False
            hits.append(now)
            return True
