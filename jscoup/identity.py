# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Turn an incoming credential into an :class:`~jscoup.models.Actor`.

The resolver never validates a token — validating is the application's job.
It only needs enough information to answer "who hit this endpoint?" while a
bug is being investigated.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from typing import Any, Dict, Mapping, Optional, Tuple

from .config import JSCoupConfig
from .models import Actor

_CLAIM_SUBJECT_KEYS = ("sub", "user_id", "uid", "id", "userId", "account_id")
_CLAIM_LABEL_KEYS = ("email", "username", "name", "preferred_username", "login")


def fingerprint_token(token: str) -> str:
    """Stable, non reversible id for a credential."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]


def decode_jwt_payload(token: str) -> Optional[Dict[str, Any]]:
    """Decode the payload segment of a JWT **without** verifying the signature."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    payload = parts[1]
    payload += "=" * (-len(payload) % 4)
    try:
        raw = base64.urlsafe_b64decode(payload.encode("ascii"))
        data = json.loads(raw.decode("utf-8"))
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return None
    return data if isinstance(data, dict) else None


class IdentityResolver:
    """Extract a credential from a request and describe its owner."""

    def __init__(self, config: JSCoupConfig):
        self.config = config

    # -- extraction -------------------------------------------------------- #

    def extract(
        self,
        headers: Optional[Mapping[str, str]] = None,
        query: Optional[Mapping[str, str]] = None,
        cookies: Optional[Mapping[str, str]] = None,
    ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """Return ``(token, source, scheme)`` for the first source that matches."""
        lowered = {str(k).lower(): v for k, v in (headers or {}).items()}
        for kind, key in self.config.token_sources:
            value = None
            if kind == "header":
                value = lowered.get(key.lower())
            elif kind == "query" and query:
                value = query.get(key)
            elif kind == "cookie" and cookies:
                value = cookies.get(key)
            if not value:
                continue
            token, scheme = self._split_scheme(str(value))
            if token:
                return token, f"{kind}:{key}", scheme
        return None, None, None

    @staticmethod
    def _split_scheme(value: str) -> Tuple[str, str]:
        parts = value.split(None, 1)
        if len(parts) == 2 and parts[0].lower() in {"bearer", "token", "jwt", "basic"}:
            return parts[1].strip(), parts[0].lower()
        return value.strip(), "raw"

    # -- resolution -------------------------------------------------------- #

    def resolve(
        self,
        token: Optional[str],
        source: Optional[str] = None,
        scheme: Optional[str] = None,
    ) -> Actor:
        if not token:
            return Actor(source=source, scheme=scheme)

        actor = Actor(
            token_fingerprint=fingerprint_token(token),
            source=source,
            scheme=scheme,
            token_preview=self._preview(token),
        )

        static = self.config.static_tokens.get(token)
        if static:
            actor.subject = str(static.get("subject") or static.get("id") or "")
            actor.label = static.get("label") or static.get("name") or static.get("email")
            actor.claims = {k: v for k, v in static.items() if k not in {"subject", "label"}}

        if self.config.identity_resolver and not actor.subject:
            try:
                extra = self.config.identity_resolver(token) or {}
            except Exception:  # a broken resolver must never break capture
                extra = {}
            if extra:
                actor.subject = str(extra.get("subject") or extra.get("id") or actor.subject or "")
                actor.label = extra.get("label") or extra.get("email") or actor.label
                actor.claims = {**actor.claims, **extra}

        if self.config.decode_jwt and not actor.subject:
            claims = decode_jwt_payload(token)
            if claims:
                actor.claims = {**claims, **actor.claims}
                actor.subject = self._first(claims, _CLAIM_SUBJECT_KEYS) or actor.subject
                actor.label = self._first(claims, _CLAIM_LABEL_KEYS) or actor.label

        if self.config.store_raw_token:
            actor.claims = {**actor.claims, "_raw_token": token}

        if not actor.label:
            actor.label = actor.subject or f"token:{actor.token_fingerprint}"
        return actor

    @staticmethod
    def _first(claims: Dict[str, Any], keys) -> Optional[str]:
        for key in keys:
            if claims.get(key) not in (None, ""):
                return str(claims[key])
        return None

    @staticmethod
    def _preview(token: str) -> str:
        if len(token) <= 12:
            return token[:3] + "***"
        return f"{token[:6]}...{token[-4:]}"
