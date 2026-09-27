# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Tests for SqlStorage's optional isolated-schema support."""

from __future__ import annotations

import pytest

sqlalchemy = pytest.importorskip("sqlalchemy")

from jscoup.storage.sql import SqlStorage  # noqa: E402


def test_sqlite_silently_ignores_the_schema_argument(tmp_path):
    """SQLite has no real schema concept — passing one must not raise, and
    must not try to qualify table names with it (which SQLite would reject)."""
    url = f"sqlite:///{tmp_path / 'events.db'}"

    storage = SqlStorage(url, schema="jscoup")

    assert storage.schema is None
    assert storage.events.schema is None
    storage.close()


def test_no_schema_argument_behaves_exactly_as_before(tmp_path):
    url = f"sqlite:///{tmp_path / 'events.db'}"

    storage = SqlStorage(url)

    assert storage.schema is None
    storage.close()


def test_sqlite_storage_still_works_normally_with_schema_passed(tmp_path):
    """The schema argument being a no-op for SQLite shouldn't break the
    underlying storage contract at all."""
    from jscoup.models import EventRecord

    url = f"sqlite:///{tmp_path / 'events.db'}"
    storage = SqlStorage(url, schema="jscoup")

    storage.save(EventRecord(kind="http", name="GET /x", status="error", severity="error"))

    assert storage.count() == 1
    storage.close()
