# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Field-level encryption for sensitive captured content, at rest.

Optional: lazy-imports ``cryptography`` at call time, never at import time,
so JSCoup stays usable with zero third-party dependencies when this isn't
used. Install with ``pip install jscoup[crypto]``.

This is field-level encryption of the sensitive parts of a captured event
(request body, headers, params), not whole-file disk encryption. When
``JSCoupConfig.encryption_key`` is set, ``core.py`` encrypts these fields
immediately before ``storage.save()`` and decrypts them immediately after
``storage.get()``/``list()``; the storage backends stay unaware either way.

A bad key or missing dependency raises immediately at construction, rather
than failing silently on first use. A single field that fails to
encrypt/decrypt is replaced with an explicit placeholder instead of falling
back to plaintext or raw ciphertext.
"""

from __future__ import annotations

import copy
import json
from typing import Any, Dict, List, Optional

from .storage.base import BaseStorage

_ENC_CONTAINER_KEY = "__jscoup_enc__"
_ENCRYPT_FAILED = "[jscoup] content omitted: encryption failed"
_DECRYPT_FAILED = "[jscoup] content unavailable: decryption failed"


class EncryptionError(Exception):
    """Raised when a field could not be encrypted or decrypted; callers
    decide the fail-closed placeholder."""


def generate_key() -> str:
    """A fresh key suitable for ``JSCoupConfig.encryption_key``."""
    from cryptography.fernet import Fernet

    return Fernet.generate_key().decode("ascii")


def _fernet(key: str) -> Any:
    from cryptography.fernet import Fernet

    return Fernet(key.encode("ascii"))


def validate_key(key: str) -> None:
    """Raise loudly if ``key`` isn't usable, instead of deferring the failure
    to the first save/read."""
    try:
        _fernet(key)
    except ImportError:
        raise
    except Exception as exc:
        raise ValueError(f"encryption_key is not a valid Fernet key: {exc}") from exc


def encrypt_text(value: Optional[str], key: str) -> Optional[str]:
    """Returns ``None`` unchanged. Raises :class:`EncryptionError` on
    failure; callers apply the fail-closed placeholder."""
    if value is None:
        return None
    try:
        return "enc:" + _fernet(key).encrypt(value.encode("utf-8")).decode("ascii")
    except Exception as exc:
        raise EncryptionError(str(exc)) from exc


def decrypt_text(value: Optional[str], key: str) -> Optional[str]:
    if value is None or not value.startswith("enc:"):
        return value
    try:
        return _fernet(key).decrypt(value[len("enc:"):].encode("ascii")).decode("utf-8")
    except Exception as exc:
        raise EncryptionError(str(exc)) from exc


def is_available() -> bool:
    try:
        import cryptography.fernet  # noqa: F401

        return True
    except ImportError:
        return False


def _encrypt_container(container: Dict[str, Any], key: str) -> Dict[str, Any]:
    """Encrypt an entire dict (``headers``/``params``) as one JSON blob, so
    nested values are covered too, not just top-level strings."""
    blob = json.dumps(container, default=str, ensure_ascii=False)
    return {_ENC_CONTAINER_KEY: encrypt_text(blob, key)}


def _looks_like_legacy_per_value_container(container: Dict[str, Any]) -> bool:
    """True for the older format where each sensitive top-level string value
    was individually prefixed with ``enc:`` instead of the container being
    encrypted as one blob."""
    return any(isinstance(v, str) and v.startswith("enc:") for v in container.values())


def _decrypt_container(container: Any, key: str) -> Any:
    if not isinstance(container, dict):
        return container
    if _ENC_CONTAINER_KEY in container:
        blob = decrypt_text(container[_ENC_CONTAINER_KEY], key)
        try:
            return json.loads(blob)
        except (TypeError, ValueError):
            raise EncryptionError("decrypted container was not valid JSON")
    if _looks_like_legacy_per_value_container(container):
        return {k: (decrypt_text(v, key) if isinstance(v, str) else v) for k, v in container.items()}
    return container  # saved before encryption was ever turned on


def encrypt_event_fields(event: Any, key: Optional[str]) -> None:
    """Mutates ``event`` in place, called immediately before
    ``storage.save()``. A field that fails to encrypt is replaced with a
    placeholder rather than stored as plaintext."""
    if not key:
        return
    try:
        event.body_preview = encrypt_text(event.body_preview, key)
    except EncryptionError:
        event.body_preview = _ENCRYPT_FAILED if event.body_preview is not None else None
    try:
        event.response_preview = encrypt_text(event.response_preview, key)
    except EncryptionError:
        event.response_preview = _ENCRYPT_FAILED if event.response_preview is not None else None
    if event.headers:
        try:
            event.headers = _encrypt_container(event.headers, key)
        except EncryptionError:
            event.headers = {_ENC_CONTAINER_KEY: None, "error": _ENCRYPT_FAILED}
    if event.params:
        try:
            event.params = _encrypt_container(event.params, key)
        except EncryptionError:
            event.params = {_ENC_CONTAINER_KEY: None, "error": _ENCRYPT_FAILED}


def decrypt_event_fields(event: Any, key: Optional[str]) -> None:
    """Mutates ``event`` in place, called immediately after
    ``storage.get()``/``storage.list()``. A field that fails to decrypt is
    replaced with a placeholder rather than returned as raw ciphertext."""
    if not key:
        return
    try:
        event.body_preview = decrypt_text(event.body_preview, key)
    except EncryptionError:
        event.body_preview = _DECRYPT_FAILED
    try:
        event.response_preview = decrypt_text(event.response_preview, key)
    except EncryptionError:
        event.response_preview = _DECRYPT_FAILED
    if event.headers:
        try:
            event.headers = _decrypt_container(event.headers, key)
        except EncryptionError:
            event.headers = {"error": _DECRYPT_FAILED}
    if event.params:
        try:
            event.params = _decrypt_container(event.params, key)
        except EncryptionError:
            event.params = {"error": _DECRYPT_FAILED}


class EncryptingStorage(BaseStorage):
    """Wraps any :class:`~jscoup.storage.base.BaseStorage` backend, encrypting
    ``body_preview``/``response_preview``/``headers``/``params`` immediately
    before writing and decrypting them immediately after reading; the
    wrapped backend never knows encryption is happening. ``save()`` encrypts
    a copy of the given event, never the caller's own object, so callers
    still holding that event see the real plaintext.
    """

    def __init__(self, inner: BaseStorage, key: str):
        validate_key(key)
        self.inner = inner
        self.key = key

    def _decrypted(self, event: Any) -> Any:
        # A copy, not the original in place: some backends (MemoryStorage)
        # return the exact persisted object by reference.
        if event is None:
            return None
        decrypted = copy.copy(event)
        decrypt_event_fields(decrypted, self.key)
        return decrypted

    def save(self, event: Any) -> None:
        to_store = copy.copy(event)
        encrypt_event_fields(to_store, self.key)
        self.inner.save(to_store)

    def get(self, event_id: str) -> Any:
        return self._decrypted(self.inner.get(event_id))

    def list(self, limit: int = 50, offset: int = 0, **filters: Any) -> List[Any]:
        return [self._decrypted(e) for e in self.inner.list(limit=limit, offset=offset, **filters)]

    def count(self, **filters: Any) -> int:
        return self.inner.count(**filters)

    def issues(self, limit: int = 50, since: Optional[float] = None) -> List[Dict[str, Any]]:
        return self.inner.issues(limit=limit, since=since)

    def summary(self, since: Optional[float] = None) -> Dict[str, Any]:
        return self.inner.summary(since=since)

    def timeline(self, buckets: int = 60, window_seconds: int = 3600) -> List[Dict[str, Any]]:
        return self.inner.timeline(buckets=buckets, window_seconds=window_seconds)

    def mark_resolved(self, event_id: str, resolved: bool = True) -> bool:
        return self.inner.mark_resolved(event_id, resolved)

    def purge(self, before: Optional[float] = None) -> int:
        return self.inner.purge(before=before)

    def close(self) -> None:
        self.inner.close()
