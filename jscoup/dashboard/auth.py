# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Dashboard login primitives: password hashing and signed session cookies.

Stdlib only (``hashlib``/``hmac``/``secrets``/``base64``/``time``), consistent
with the rest of the library having zero runtime dependencies. A raw password
is only ever seen by :func:`hash_password`/:func:`verify_password`; everything
else deals in the PBKDF2 hash or in signed, expiring session tokens.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import secrets
import time
from typing import Dict, Optional, Sequence, Tuple

SESSION_COOKIE_NAME = "jscoup_session"

_PBKDF2_ITERATIONS = 600_000
_HASH_ALGO = "sha256"

AttemptStore = Dict[str, Tuple[int, float]]


# --------------------------------------------------------------------------- #
# passwords
# --------------------------------------------------------------------------- #


def hash_password(password: str) -> str:
    """Hash a plaintext password for :attr:`JSCoupConfig.dashboard_password_hash`."""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(_HASH_ALGO, password.encode("utf-8"), salt, _PBKDF2_ITERATIONS)
    return f"pbkdf2_{_HASH_ALGO}${_PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_username(candidate: str, expected: str) -> bool:
    """Constant-time username comparison (usernames aren't secret, but it's free)."""
    return hmac.compare_digest(candidate.encode("utf-8"), expected.encode("utf-8"))


def verify_password(password: str, encoded: Optional[str]) -> bool:
    """Check a plaintext password against a hash produced by :func:`hash_password`."""
    if not encoded:
        return False
    try:
        algo, iterations_text, salt_hex, digest_hex = encoded.split("$")
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
        iterations = int(iterations_text)
    except (ValueError, AttributeError):
        return False
    candidate = hashlib.pbkdf2_hmac(algo.replace("pbkdf2_", "", 1), password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(candidate, expected)


# --------------------------------------------------------------------------- #
# sessions
# --------------------------------------------------------------------------- #


def sign_session(username: str, secret: str, ttl_seconds: float) -> str:
    """Build a tamper-evident session token for ``username``, valid ``ttl_seconds``."""
    expiry = time.time() + ttl_seconds
    payload = f"{username}|{expiry}".encode("utf-8")
    b64_payload = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
    signature = hmac.new(secret.encode("utf-8"), b64_payload.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{b64_payload}.{signature}"


def verify_session(cookie_value: Optional[str], secret: str) -> Optional[str]:
    """Return the username a session was signed for, or None if missing/tampered/expired."""
    if not cookie_value or "." not in cookie_value:
        return None
    b64_payload, _, signature = cookie_value.partition(".")
    expected = hmac.new(secret.encode("utf-8"), b64_payload.encode("ascii"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        return None
    try:
        padded = b64_payload + "=" * (-len(b64_payload) % 4)
        username, _, expiry_text = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8").partition("|")
        expiry = float(expiry_text)
    except (ValueError, UnicodeDecodeError):
        return None
    if not username or time.time() >= expiry:
        return None
    return username


def build_set_cookie_header(name: str, value: str, max_age: Optional[int], secure: bool = False) -> str:
    """Build a ``Set-Cookie`` header value. ``max_age=None`` clears the cookie."""
    parts = [f"{name}={value}", "Path=/", "HttpOnly", "SameSite=Lax"]
    parts.append("Max-Age=0" if max_age is None else f"Max-Age={int(max_age)}")
    if secure:
        parts.append("Secure")
    return "; ".join(parts)


# --------------------------------------------------------------------------- #
# a tiny, dependency-free failed-login rate limiter
# --------------------------------------------------------------------------- #
# state shape: {key: (failed_attempts, locked_until_timestamp)}


def is_locked(store: AttemptStore, key: str) -> bool:
    _, locked_until = store.get(key, (0, 0.0))
    return time.time() < locked_until


def record_failure(store: AttemptStore, key: str, max_attempts: int, lockout_seconds: float) -> None:
    attempts, _ = store.get(key, (0, 0.0))
    attempts += 1
    locked_until = time.time() + lockout_seconds if attempts >= max_attempts else 0.0
    store[key] = (attempts, locked_until)


def clear_failures(store: AttemptStore, key: str) -> None:
    store.pop(key, None)


# --------------------------------------------------------------------------- #
# IP allowlist — a network-level gate, checked before any login attempt
# --------------------------------------------------------------------------- #


def ip_allowed(client_ip: Optional[str], allowed: Optional[Sequence[str]]) -> bool:
    """True if ``client_ip`` matches one of ``allowed`` (exact IPs or CIDR
    ranges, e.g. ``"10.0.0.0/8"``). An empty/None ``allowed`` means
    unrestricted. An unparseable client_ip or entry is treated as no-match
    rather than raising.
    """
    if not allowed:
        return True
    if not client_ip:
        return False
    # X-Forwarded-For style values can be "client, proxy1, proxy2" — the
    # original client is always the first hop.
    first_hop = client_ip.split(",")[0].strip()
    try:
        addr = ipaddress.ip_address(first_hop)
    except ValueError:
        return False
    for entry in allowed:
        try:
            if "/" in entry:
                if addr in ipaddress.ip_network(entry, strict=False):
                    return True
            elif addr == ipaddress.ip_address(entry):
                return True
        except ValueError:
            continue
    return False


def dummy_password_hash():
    # Fixed public dummy record. Same cost as a newly created real account.
    return "pbkdf2_sha256$600000$" + "00" * 16 + "$" + "00" * 32
