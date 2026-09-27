# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Tests for jscoup.storage.mongo.MongoStorage — the document-database
counterpart to SqlStorage, requested to close the "SQLite doesn't survive a
serverless function's ephemeral disk" gap for teams already running Mongo.

Uses `mongomock` (an in-memory fake MongoDB) instead of a real server —
skipped entirely if either `pymongo` or `mongomock` isn't installed.
"""

from __future__ import annotations

import json
import os
import time

import pytest

pytest.importorskip("pymongo")
mongomock = pytest.importorskip("mongomock")

import pymongo  # noqa: E402

from jscoup import JSCoup  # noqa: E402
from jscoup.models import Actor, EventRecord, QueryRecord  # noqa: E402
from jscoup.storage.mongo import MongoStorage  # noqa: E402


@pytest.fixture(autouse=True)
def _patch_mongo_client(request, monkeypatch):
    # real_server-marked tests want the genuine pymongo.MongoClient against
    # a real server, not the in-memory fake — see test_summary_matches_a_
    # hand_computed_result_against_real_mongo below.
    if request.node.get_closest_marker("real_server") is None:
        monkeypatch.setattr(pymongo, "MongoClient", mongomock.MongoClient)


@pytest.fixture
def storage():
    return MongoStorage(url="mongodb://localhost/", database="jscoup-test")


def _event(**overrides) -> EventRecord:
    fields = dict(id="e1", name="job", status="ok", category="none", ts=time.time())
    fields.update(overrides)
    return EventRecord(**fields)


def test_save_and_get_roundtrip(storage):
    event = _event(id="e1", body_preview="hello world")
    storage.save(event)
    fetched = storage.get("e1")
    assert fetched is not None
    assert fetched.body_preview == "hello world"


def test_resaving_the_same_id_replaces_rather_than_duplicates(storage):
    """Unlike the SQL backends (Finding 9), there is no separate child table
    to desynchronise here — replace_one(upsert=True) on the whole document
    is naturally atomic. This pins that property."""
    event = _event(id="e1", queries=[QueryRecord(sql="SELECT 1"), QueryRecord(sql="SELECT 2")])
    storage.save(event)
    storage.save(event)
    assert storage.count() == 1
    assert len(storage.get("e1").queries) == 2


def test_list_filters_by_status_and_category():
    storage_local = MongoStorage(url="mongodb://localhost/", database="jscoup-test-2")
    storage_local.save(_event(id="a", status="error", category="database"))
    storage_local.save(_event(id="b", status="ok", category="none"))
    errors = storage_local.list(status="error")
    assert len(errors) == 1 and errors[0].id == "a"


def test_actor_and_search_filters(storage):
    storage.save(_event(id="a", name="checkout", actor=Actor(subject="user-1")))
    storage.save(_event(id="b", name="refund", actor=Actor(subject="user-2")))
    assert [e.id for e in storage.list(actor="user-1")] == ["a"]
    assert [e.id for e in storage.list(search="refund")] == ["b"]


def test_issues_groups_by_fingerprint(storage):
    storage.save(_event(id="a", status="error", fingerprint="fp1", error_type="ValueError"))
    storage.save(_event(id="b", status="error", fingerprint="fp1", error_type="ValueError"))
    storage.save(_event(id="c", status="error", fingerprint="fp2", error_type="KeyError"))
    issues = storage.issues()
    by_fp = {i["fingerprint"]: i["count"] for i in issues}
    assert by_fp == {"fp1": 2, "fp2": 1}


def test_summary_counts(storage):
    storage.save(_event(id="a", status="ok"))
    storage.save(_event(id="b", status="error", category="database"))
    storage.save(_event(id="c", status="slow"))
    summary = storage.summary()
    assert summary["events"] == 3
    assert summary["errors"] == 1
    assert summary["slow"] == 1
    assert summary["ok"] == 1


def test_summary_breakdowns_and_distinct_counts(storage):
    """summary() used to load every matching document into application
    memory and count in Python — replaced with a single server-side
    $facet aggregation (see storage/mongo.py). This pins the full shape,
    including the distinct-count facets (issues/actors) that are easiest
    to get wrong when porting Python set() logic into an aggregation
    pipeline."""
    storage.save(_event(id="a", status="error", category="database", name="POST /orders",
                         fingerprint="fp1", duration_ms=10, actor=Actor(subject="u1", label="alice")))
    storage.save(_event(id="b", status="error", category="database", name="POST /orders",
                         fingerprint="fp1", duration_ms=20, actor=Actor(subject="u1", label="alice")))
    storage.save(_event(id="c", status="error", category="validation", name="POST /reservations",
                         fingerprint="fp2", duration_ms=5, actor=Actor(subject="u2", label="bob")))
    storage.save(_event(id="d", status="ok", category="none", name="GET /health", duration_ms=1))

    summary = storage.summary()

    assert summary["events"] == 4
    assert summary["errors"] == 3
    assert summary["ok"] == 1
    assert summary["slow"] == 0
    assert summary["issues"] == 2  # distinct fingerprints among errors: fp1, fp2
    assert summary["actors"] == 2  # distinct actor.subject: u1, u2
    assert summary["max_ms"] == 20
    assert summary["queries"] == 0
    by_category = {row["category"]: row["count"] for row in summary["by_category"]}
    assert by_category == {"database": 2, "validation": 1}
    by_endpoint = {row["name"]: row["count"] for row in summary["by_endpoint"]}
    assert by_endpoint == {"POST /orders": 2, "POST /reservations": 1}
    by_actor = {row["actor"]: row["count"] for row in summary["by_actor"]}
    assert by_actor == {"alice": 2, "bob": 1}


@pytest.mark.real_server
def test_summary_matches_a_hand_computed_result_against_real_mongo():
    """Runs the same $facet pipeline against a real MongoDB server instead
    of mongomock — mongomock's aggregation support is a partial
    reimplementation and has previously diverged from real MongoDB
    semantics for edge cases (e.g. $ifNull/$cond typing), so this is the
    genuine validation for the summary() rewrite. Skipped unless
    JSCOUP_TEST_MONGO_URL points at a real, reachable MongoDB (see CI's
    `mongo` service container).
    """
    url = os.environ.get("JSCOUP_TEST_MONGO_URL")
    if not url:
        pytest.skip("set JSCOUP_TEST_MONGO_URL to a real MongoDB to run this")

    import uuid

    database = f"jscoup_test_{uuid.uuid4().hex[:8]}"
    storage = MongoStorage(url=url, database=database)
    try:
        storage.save(_event(id="a", status="error", category="database", fingerprint="fp1",
                             duration_ms=10, actor=Actor(subject="u1", label="alice")))
        storage.save(_event(id="b", status="error", category="database", fingerprint="fp1",
                             duration_ms=20, actor=Actor(subject="u1", label="alice")))
        storage.save(_event(id="c", status="ok", category="none", duration_ms=1))

        summary = storage.summary()

        assert summary["events"] == 3
        assert summary["errors"] == 2
        assert summary["ok"] == 1
        assert summary["issues"] == 1
        assert summary["actors"] == 1
        assert summary["max_ms"] == 20
        assert summary["avg_ms"] == round((10 + 20 + 1) / 3, 2)
    finally:
        storage.client.drop_database(database)
        storage.close()


def test_timeline_buckets_recent_events(storage):
    storage.save(_event(id="a", status="ok", ts=time.time()))
    series = storage.timeline(buckets=10, window_seconds=3600)
    assert sum(b["ok"] for b in series) == 1


def test_mark_resolved(storage):
    storage.save(_event(id="a"))
    assert storage.mark_resolved("a", True) is True
    assert storage.get("a").resolved is True
    assert storage.mark_resolved("does-not-exist") is False


def test_purge(storage):
    storage.save(_event(id="old", ts=time.time() - 1_000_000))
    storage.save(_event(id="new", ts=time.time()))
    deleted = storage.purge(before=time.time() - 100)
    assert deleted == 1
    assert storage.count() == 1


def test_from_file_json(tmp_path):
    config_path = tmp_path / "mongo.json"
    config_path.write_text(json.dumps({"url": "mongodb://localhost/", "database": "jscoup-file-test"}))
    storage = MongoStorage.from_file(str(config_path))
    storage.save(_event(id="a"))
    assert storage.count() == 1


def test_jscoup_end_to_end_with_mongo_storage():
    storage = MongoStorage(url="mongodb://localhost/", database="jscoup-e2e")
    bl = JSCoup("mongo-test", storage=storage, capture_success=True)
    with bl.capture(kind="service", name="job") as ctx:
        ctx.body_preview = "stored in mongo"

    events = bl.storage.list()
    assert len(events) == 1
    assert events[0].body_preview == "stored in mongo"
