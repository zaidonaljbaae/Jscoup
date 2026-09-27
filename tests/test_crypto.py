# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Tests for jscoup.crypto — field-level encryption at rest, skipped entirely
if the optional `cryptography` dependency isn't installed."""

from __future__ import annotations

import pytest

pytest.importorskip("cryptography")

from jscoup import JSCoup, MemoryStorage
from jscoup.crypto import EncryptingStorage, EncryptionError, decrypt_text, encrypt_text, generate_key
from jscoup.storage.sqlite import SQLiteStorage


def test_generate_key_returns_a_usable_fernet_key():
    key = generate_key()
    assert isinstance(key, str) and len(key) > 20


def test_encrypt_then_decrypt_roundtrips():
    key = generate_key()
    ciphertext = encrypt_text("super secret body", key)
    assert ciphertext != "super secret body"
    assert ciphertext.startswith("enc:")
    assert decrypt_text(ciphertext, key) == "super secret body"


def test_decrypt_with_the_wrong_key_raises_instead_of_returning_ciphertext():
    """A silent fallback to the raw ciphertext used to look like "just some
    garbled string" to anything reading it, rather than a clear failure —
    decrypt_text now raises so the caller (decrypt_event_fields) can apply
    an explicit, honest placeholder instead. See test_event_fields below for
    that higher-level, fail-closed behavior."""
    key = generate_key()
    other_key = generate_key()
    ciphertext = encrypt_text("secret", key)

    with pytest.raises(EncryptionError):
        decrypt_text(ciphertext, other_key)


def test_plaintext_passed_through_decrypt_untouched():
    key = generate_key()
    assert decrypt_text("never encrypted", key) == "never encrypted"


def test_none_values_pass_through_both_directions():
    key = generate_key()
    assert encrypt_text(None, key) is None
    assert decrypt_text(None, key) is None


def test_jbl_stores_events_encrypted_at_rest_but_reads_back_plaintext(tmp_path):
    key = generate_key()
    bl = JSCoup(
        "crypto-test", storage=SQLiteStorage(db_path=str(tmp_path / "events.db")),
        encryption_key=key, capture_success=True,
    )

    with bl.capture(kind="http", name="job") as ctx:
        ctx.body_preview = "super secret request body"
        ctx.params = {"account_number": "AB1234567"}  # not a name the redactor scrubs
        ctx.headers = {"X-Client-Note": "internal routing detail"}

    # the raw row on disk must not contain the plaintext
    import sqlite3

    raw_conn = sqlite3.connect(str(tmp_path / "events.db"))
    raw_payload = raw_conn.execute("SELECT payload FROM events LIMIT 1").fetchone()[0]
    raw_conn.close()
    assert "super secret request body" not in raw_payload
    assert "AB1234567" not in raw_payload

    # reading it back through the library gives the real plaintext
    event = bl.storage.list()[0]
    assert event.body_preview == "super secret request body"
    assert event.params["account_number"] == "AB1234567"
    assert event.headers["X-Client-Note"] == "internal routing detail"


def test_on_event_hook_sees_plaintext_not_ciphertext(tmp_path):
    """save() must encrypt a copy, never the caller's own event object —
    anything holding that same reference (like on_event) still sees real
    data, since it's this process's own memory, not an external reader."""
    key = generate_key()
    seen = {}

    def on_event(event):
        seen["body_preview"] = event.body_preview

    bl = JSCoup(
        "crypto-hook-test", storage=SQLiteStorage(db_path=str(tmp_path / "events.db")),
        encryption_key=key, capture_success=True, on_event=on_event,
    )

    with bl.capture(kind="http", name="job") as ctx:
        ctx.body_preview = "plaintext for the hook"

    assert seen["body_preview"] == "plaintext for the hook"


def test_encrypting_storage_wraps_any_backend_transparently():
    inner = MemoryStorage()
    key = generate_key()
    storage = EncryptingStorage(inner, key)

    bl = JSCoup("wrap-test", storage=storage, capture_success=True)
    with bl.capture(kind="http", name="job") as ctx:
        ctx.body_preview = "wrapped secret"

    assert storage.list()[0].body_preview == "wrapped secret"
    # the underlying MemoryStorage instance holds the ciphertext directly
    assert inner.list()[0].body_preview != "wrapped secret"


def test_encrypting_storage_rejects_a_malformed_key_immediately():
    """The key must be validated once, at setup — not discovered later as a
    field that silently never got encrypted."""
    with pytest.raises(ValueError):
        EncryptingStorage(MemoryStorage(), "not-a-valid-fernet-key")


def test_nested_values_inside_params_are_encrypted_too():
    """encrypt_event_fields used to only touch top-level string values in
    params/headers — a nested dict or list value passed through completely
    untouched. The fix encrypts the whole structure as one blob."""
    key = generate_key()
    inner = MemoryStorage()
    storage = EncryptingStorage(inner, key)

    bl = JSCoup("nested-test", storage=storage, capture_success=True)
    with bl.capture(kind="http", name="job") as ctx:
        ctx.params = {"user": {"note": "vip customer, handle personally"}, "flags": ["priority", "fragile"]}

    raw_event = inner.list()[0]
    assert "vip customer" not in repr(raw_event.params)
    assert "priority" not in repr(raw_event.params)

    event = storage.list()[0]
    assert event.params["user"]["note"] == "vip customer, handle personally"
    assert event.params["flags"] == ["priority", "fragile"]


def test_no_encryption_key_means_plaintext_storage(tmp_path):
    bl = JSCoup(
        "no-crypto-test", storage=SQLiteStorage(db_path=str(tmp_path / "events.db")),
        capture_success=True,
    )
    with bl.capture(kind="http", name="job") as ctx:
        ctx.body_preview = "plain as day"

    import sqlite3

    raw_conn = sqlite3.connect(str(tmp_path / "events.db"))
    raw_payload = raw_conn.execute("SELECT payload FROM events LIMIT 1").fetchone()[0]
    raw_conn.close()
    assert "plain as day" in raw_payload
