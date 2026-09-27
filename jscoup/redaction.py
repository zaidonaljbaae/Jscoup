# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Scrubbing of sensitive values before anything is written to disk."""

from __future__ import annotations

import json
import re
from typing import Any, Iterable, List

_SEPARATORS = re.compile(r"[^a-z0-9]+")
_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")

_CARD = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*")
_EMAILISH_SECRET = re.compile(r"(?i)(password|secret|token)\s*[:=]\s*[^\s&]+")
_QUOTED_SECRET = re.compile(
    r'(?i)(["\']?(?:password|passwd|pwd|secret|token|api_?key|authorization)["\']?\s*[:=]\s*)'
    r'(["\'])(?:(?!\2).)*\2'
)


class Redactor:
    """Replace sensitive values with a mask, recursively.

    The redactor is intentionally conservative: it matches on key names first
    (cheap and reliable) and then applies a couple of value level patterns for
    things that leak through free-form strings.
    """

    def __init__(self, sensitive_keys: Iterable[str], mask: str = "[redacted]", max_depth: int = 6):
        sensitive_keys = tuple(sensitive_keys)
        self.sensitive_keys = {self._normalize(k) for k in sensitive_keys}
        self.mask = mask
        self.max_depth = max_depth
        keys = "|".join(re.escape(str(k)) for k in sensitive_keys)
        self._custom = re.compile(r"(?i)([\"']?(?:" + keys + r")[\"']?\s*[:=]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s,}&]+)") if keys else None

    @staticmethod
    def _normalize(key: Any) -> str:
        """Collapse case and separator style so ``api_key``, ``api-key`` and
        ``apiKey``/``ApiKey`` are all the same candidate."""
        text = _CAMEL_BOUNDARY.sub("_", str(key))
        return _SEPARATORS.sub("_", text.lower()).strip("_")

    def is_sensitive(self, key: str) -> bool:
        normalized = self._normalize(key)
        return any(candidate in normalized for candidate in self.sensitive_keys)

    def scrub(self, value: Any, depth: int = 0) -> Any:
        if depth > self.max_depth:
            return "[truncated]"
        if isinstance(value, dict):
            out = {}
            for key, item in value.items():
                if self.is_sensitive(key):
                    out[key] = self.mask
                else:
                    out[key] = self.scrub(item, depth + 1)
            return out
        if isinstance(value, (list, tuple, set)):
            return [self.scrub(item, depth + 1) for item in list(value)[:100]]
        if isinstance(value, str):
            return self.scrub_text(value)
        if isinstance(value, (int, float, bool)) or value is None:
            return value
        try:
            return self.scrub_text(repr(value))
        except Exception:
            return "[unrepresentable]"

    def scrub_text(self, text: str, limit: int = 4000) -> str:
        if not text:
            return text
        if self._custom:
            text = self._custom.sub(lambda m: m.group(1) + repr(self.mask), text)
        text = _QUOTED_SECRET.sub(lambda m: f'{m.group(1)}"{self.mask}"', text)
        text = _JWT.sub(self.mask, text)
        text = _CARD.sub(self.mask, text)
        text = _EMAILISH_SECRET.sub(r"\1=" + self.mask, text)
        if len(text) > limit:
            text = text[:limit] + f"... [+{len(text) - limit} chars]"
        return text

    def scrub_body(self, raw: str, limit: int = 4000) -> str:
        """Scrub a raw request body.

        JSON bodies are parsed and scrubbed key by key (the reliable path);
        anything else falls back to pattern based masking.
        """
        if not raw:
            return raw
        stripped = raw.lstrip()
        if stripped[:1] in ("{", "["):
            try:
                payload = json.loads(raw)
            except (json.JSONDecodeError, ValueError):
                return self.scrub_text(raw, limit)
            cleaned = json.dumps(self.scrub(payload), ensure_ascii=False, default=str)
            return cleaned[:limit]
        return self.scrub_text(raw, limit)

    def scrub_headers(self, headers: Any) -> dict:
        try:
            items = headers.items()
        except AttributeError:
            items = dict(headers or {}).items()
        out = {}
        for key, value in items:
            key = str(key)
            out[key] = self.mask if self.is_sensitive(key) else self.scrub_text(str(value), 500)
        return out


def default_redactor(sensitive_keys: List[str], mask: str = "[redacted]") -> Redactor:
    return Redactor(sensitive_keys, mask)
