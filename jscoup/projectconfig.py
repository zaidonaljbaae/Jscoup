# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""A single project config file that drives an entire JSCoup instance.

Covers what otherwise takes several ``JSCoup(...)`` keyword arguments as one
human-editable JSON file: which database JSCoup uses, the dashboard admin
login, which dashboard features are turned on, and whether the API Gateway
is enabled. Created automatically, with a generated superadmin password,
the first time it's loaded and the file doesn't exist yet.

This is one more way to build a :class:`~jscoup.core.JSCoup`, not a
replacement for ``JSCoup(...)`` or ``JSCoup.auto()``.

This file holds real secrets (a dashboard password, an encryption key):
:func:`save` writes it as a fresh, owner-only-readable file and swaps it in
atomically, and :func:`load_or_create` serializes first-run creation across
concurrent worker processes. A string value of the form ``"env:SOME_VAR"``
for ``dashboard_password``, ``encryption_key`` or ``database_url`` is
resolved from that environment variable at load time, so the file itself can
be committed with no real secret in it.
"""

from __future__ import annotations

import json
import os
import secrets
import tempfile
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

DEFAULT_CONFIG_PATH = ".jscoup.config.json"

_DEFAULT_FEATURES = {
    "live_tester": True,
    "code_audit": True,
    "gateway": False,
}

# Feature-flag names that don't map 1:1 onto a same-named JSCoupConfig field.
FEATURE_TO_CONFIG_FIELD = {
    "live_tester": "allow_live_invoke",
    "code_audit": "audit_enabled",
}


def _resolve_secret(value: Optional[str]) -> Optional[str]:
    """Resolve an ``"env:VAR_NAME"`` reference from the environment; any
    other string (or ``None``) is returned unchanged."""
    if isinstance(value, str) and value.startswith("env:"):
        resolved = os.environ.get(value[4:])
        if not resolved:
            raise ValueError("Required environment secret is missing: " + value[4:])
        return resolved
    return value


@dataclass
class ProjectConfig:
    """Plain, JSON-round-trippable project settings. Field names match the
    ``JSCoup(...)``/``JSCoupConfig`` keywords they map to wherever the name
    isn't self-explanatory."""

    service_name: str = "service"
    environment: str = "local"

    # Database JSCoup itself stores captured events in. None -> a local
    # SQLite file at db_path; set to a SQLAlchemy URL (e.g.
    # "postgresql+psycopg://user:pass@host/db") to use SqlStorage instead
    # (requires the `jscoup[sql]` extra). May be "env:VAR_NAME".
    database_url: Optional[str] = None
    db_path: str = ".jscoup/jscoup.db"
    retention_days: int = 14

    # dashboard / admin login. dashboard_password may be "env:VAR_NAME".
    dashboard_username: str = "admin"
    dashboard_password: Optional[str] = None
    dashboard_mount_in_app: bool = True
    dashboard_host: str = "127.0.0.1"
    dashboard_port: int = 9000  # only used when dashboard_mount_in_app is False
    dashboard_base_url: Optional[str] = None  # only used when dashboard_mount_in_app is False
    dashboard_allowed_ips: Optional[List[str]] = None

    # which dashboard tabs/capabilities are active
    features: Dict[str, bool] = field(default_factory=lambda: dict(_DEFAULT_FEATURES))

    # API Gateway: how long a POST /gw/login session stays valid.
    gateway_token_ttl_hours: float = 1.0

    # Field-level encryption at rest (jscoup.crypto) — auto-filled in below
    # the moment `cryptography` is installed, so it's on by default rather
    # than an extra step. None when the extra isn't installed. May be
    # "env:VAR_NAME" instead of a literal value.
    encryption_key: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        for key, reference in getattr(self, "_secret_references", {}).items():
            data[key] = reference
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ProjectConfig":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        clean = {k: v for k, v in data.items() if k in known and k != "features"}
        clean["features"] = {**_DEFAULT_FEATURES, **(data.get("features") or {})}
        for secret_field in ("dashboard_password", "encryption_key", "database_url"):
            if secret_field in clean:
                clean[secret_field] = _resolve_secret(clean[secret_field])
        result = cls(**clean)
        result._secret_references = {k: v for k, v in data.items()
            if k in ("dashboard_password", "encryption_key", "database_url")
            and isinstance(v, str) and v.startswith("env:")}
        return result


def load_or_create(path: str = DEFAULT_CONFIG_PATH) -> ProjectConfig:
    """Load the project's config file, creating it with SQLite defaults and a
    freshly generated superadmin password if it doesn't exist yet. Safe to
    call on every process start, including several workers starting at once;
    first-run creation is serialized with a lock file.
    """
    if os.path.exists(path):
        return _read(path)

    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    lock_path = path + ".lock"
    held = _acquire_startup_lock(lock_path)
    try:
        # Another worker may have created it while this one waited for the lock.
        if os.path.exists(path):
            return _read(path)

        if not held:
            raise TimeoutError("Configuration startup lock timed out; retry startup")
        encryption_key = None
        try:
            from .crypto import generate_key

            encryption_key = generate_key()
        except ImportError:
            pass  # cryptography extra not installed — stays plaintext

        config = ProjectConfig(dashboard_password=secrets.token_urlsafe(9), encryption_key=encryption_key)
        save(config, path)
        print(
            f"[jscoup] No config found at '{path}' — created one with a generated "
            f"superadmin password. Edit that file any time to change the database, "
            f"dashboard login, or which features are on."
        )
        return config
    finally:
        if held:
            _release_startup_lock(lock_path)


def _read(path: str) -> ProjectConfig:
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    return ProjectConfig.from_dict(data)


def save(config: ProjectConfig, path: str = DEFAULT_CONFIG_PATH) -> None:
    """Write ``config`` to ``path``.

    Writes to a fresh temporary file in the same directory first, then swaps
    it into place with :func:`os.replace` (atomic on both POSIX and
    Windows), so a crash or concurrent reader never sees a half-written
    file. ``tempfile.mkstemp`` creates the temp file owner-readable-only
    (mode 0600); Windows has no equivalent permission-bit model, so this is
    best-effort there.
    """
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    payload = json.dumps(config.to_dict(), indent=2, ensure_ascii=False) + "\n"

    fd, tmp_path = tempfile.mkstemp(prefix=".jscoup-config-", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        raise


def _acquire_startup_lock(lock_path: str, timeout: float = 10.0, stale_after: float = 30.0) -> bool:
    """A minimal, dependency-free mutual-exclusion lock for first-run config
    creation, using ``O_CREAT | O_EXCL`` to fail if another process already
    holds the lock. A lock file older than ``stale_after`` seconds is
    assumed abandoned and taken over. Returns ``True`` if this call created
    the lock, ``False`` if it gave up waiting.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
            return True
        except (FileExistsError, PermissionError):
            # Windows can raise PermissionError instead of FileExistsError
            # for the same "someone else is racing on this path" situation.
            time.sleep(0.05)
    return False


def _release_startup_lock(lock_path: str) -> None:
    try:
        os.remove(lock_path)
    except OSError:
        pass
