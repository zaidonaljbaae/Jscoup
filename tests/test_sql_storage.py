# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Tests for jscoup.storage.sql.SqlStorage — the real-database backend.

Runs against a throwaway SQLite file *through SQLAlchemy* (not through
jscoup.storage.sqlite.SQLiteStorage) specifically to prove the cross-engine
``metadata.create_all()`` table-creation path and the SQLAlchemy Core query
building work end to end, without needing a real Postgres/MySQL server in
CI — the same Core code runs unmodified against any SQLAlchemy dialect.
"""

import os
import threading
import time

import pytest

sqlalchemy = pytest.importorskip("sqlalchemy")

from jscoup.models import Actor, EventRecord, QueryRecord  # noqa: E402
from jscoup.storage.sql import SqlStorage  # noqa: E402


@pytest.fixture
def storage(tmp_path):
    url = f"sqlite:///{tmp_path / 'events.db'}"
    store = SqlStorage(url, max_events=1000, retention_days=14)
    yield store
    store.close()


def _event(**overrides):
    defaults = dict(
        kind="http", name="GET /widgets", status="error", severity="error",
        category="database", method="GET", path="/widgets", route="/widgets",
        status_code=500, duration_ms=12.5, error_type="ValueError",
        error_message="boom", fingerprint="fp-1", culprit="app.views.widgets",
        service="test-service", environment="test",
        actor=Actor(subject="u1", label="alice", token_fingerprint="tok-1"),
        queries=[QueryRecord(sql="SELECT 1", duration_ms=1.2, backend="sqlite3")],
    )
    defaults.update(overrides)
    return EventRecord(**defaults)


def test_creates_tables_and_round_trips_an_event(storage):
    event = _event()
    storage.save(event)

    fetched = storage.get(event.id)

    assert fetched is not None
    assert fetched.name == "GET /widgets"
    assert fetched.status == "error"
    assert fetched.actor.label == "alice"
    assert len(fetched.queries) == 1
    assert fetched.queries[0].sql == "SELECT 1"


def test_list_filters_by_status_and_actor(storage):
    storage.save(_event(fingerprint="fp-1"))
    storage.save(_event(fingerprint="fp-2", status="ok", severity="info",
                         actor=Actor(subject="u2", label="bob", token_fingerprint="tok-2")))

    errors = storage.list(status="error")
    bobs = storage.list(actor="bob")

    assert len(errors) == 1
    assert errors[0].fingerprint == "fp-1"
    assert len(bobs) == 1
    assert bobs[0].actor.label == "bob"


def test_count_matches_list_filters(storage):
    storage.save(_event(fingerprint="fp-1"))
    storage.save(_event(fingerprint="fp-2", status="ok", severity="info"))

    assert storage.count() == 2
    assert storage.count(status="error") == 1


def test_issues_groups_by_fingerprint(storage):
    storage.save(_event(fingerprint="fp-1"))
    storage.save(_event(fingerprint="fp-1"))
    storage.save(_event(fingerprint="fp-2"))

    issues = storage.issues()

    by_fp = {i["fingerprint"]: i["count"] for i in issues}
    assert by_fp["fp-1"] == 2
    assert by_fp["fp-2"] == 1


def test_summary_reports_totals_and_breakdowns(storage):
    storage.save(_event(fingerprint="fp-1"))
    storage.save(_event(fingerprint="fp-2", status="ok", severity="info"))

    summary = storage.summary()

    assert summary["events"] == 2
    assert summary["errors"] == 1
    assert summary["ok"] == 1
    assert any(row["category"] == "database" for row in summary["by_category"])


def test_timeline_buckets_recent_events(storage):
    storage.save(_event())

    buckets = storage.timeline(buckets=10, window_seconds=3600)

    assert len(buckets) == 10
    assert sum(b["errors"] + b["slow"] + b["ok"] for b in buckets) == 1


def test_mark_resolved_updates_the_row(storage):
    event = _event()
    storage.save(event)

    changed = storage.mark_resolved(event.id, True)

    assert changed is True
    assert storage.get(event.id).resolved is True


def test_purge_deletes_matching_events_and_their_queries(storage):
    storage.save(_event(fingerprint="fp-old"))
    storage.save(_event(fingerprint="fp-new"))

    deleted = storage.purge(before=time.time() + 1)

    assert deleted == 2
    assert storage.count() == 0


def test_save_is_idempotent_for_the_same_event_id(storage):
    event = _event()
    storage.save(event)
    event.status = "ok"
    storage.save(event)  # same id — must replace, not duplicate

    assert storage.count() == 1
    assert storage.get(event.id).status == "ok"


def test_constructed_from_discrete_connection_parts_instead_of_a_url(tmp_path):
    """The 'connection built from host/port/username/... instead of a
    hand-written URL' path, exercised end to end against a real (throwaway)
    SQLite database rather than mocking SQLAlchemy."""
    store = SqlStorage(drivername="sqlite", database=str(tmp_path / "discrete.db"))
    try:
        store.save(_event(id="discrete-1"))
        assert store.get("discrete-1") is not None
    finally:
        store.close()


def test_concurrent_construction_against_a_fresh_database_does_not_crash(tmp_path):
    """Regression test for a boot-time race found while embedding this
    library in three multi-worker demo services: gunicorn workers forked
    without --preload each import the app and construct SqlStorage
    independently, so several processes can call
    metadata.create_all(checkfirst=True) against the same brand-new
    database at once. checkfirst is check-then-create, not atomic, so one
    loses to a duplicate-object error from the database — even though the
    tables it wanted now exist, created by the winner. Ten threads racing
    to construct against the same fresh SQLite file must all succeed.
    """
    url = f"sqlite:///{tmp_path / 'race.db'}"
    stores: list = []
    errors: list = []
    barrier = threading.Barrier(10)

    def build():
        barrier.wait()
        try:
            stores.append(SqlStorage(url, connect_args={"timeout": 30}))
        except Exception as exc:  # pragma: no cover - failure path under test
            errors.append(exc)

    threads = [threading.Thread(target=build) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    try:
        assert errors == []
        assert len(stores) == 10
        stores[0].save(_event(id="after-race"))
        assert stores[0].get("after-race") is not None
    finally:
        for store in stores:
            store.close()


@pytest.mark.real_server
def test_concurrent_construction_against_real_postgres_does_not_crash():
    """Same regression as above, but against a real PostgreSQL server —
    the exact database/driver combination (psycopg2 raising
    ``UniqueViolation`` on ``pg_class_relname_nsp_index``) that produced the
    original crash. Skipped unless JSCOUP_TEST_PG_URL points at a real,
    reachable, empty-schema-safe Postgres instance (see CI's `postgres`
    service container).
    """
    url = os.environ.get("JSCOUP_TEST_PG_URL")
    if not url:
        pytest.skip("set JSCOUP_TEST_PG_URL to a real Postgres to run this")

    import uuid

    schema = f"jscoup_race_{uuid.uuid4().hex[:8]}"
    stores: list = []
    errors: list = []
    barrier = threading.Barrier(8)

    def build():
        barrier.wait()
        try:
            stores.append(SqlStorage(url, schema=schema))
        except Exception as exc:  # pragma: no cover - failure path under test
            errors.append(exc)

    threads = [threading.Thread(target=build) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    try:
        assert errors == [], f"construction failed under real concurrency: {errors}"
        assert len(stores) == 8
        stores[0].save(_event(id="pg-race"))
        assert stores[0].get("pg-race") is not None
    finally:
        for store in stores:
            store.close()
        # best-effort cleanup of the throwaway schema
        import sqlalchemy as sa

        engine = sa.create_engine(url)
        with engine.begin() as conn:
            conn.execute(sa.text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        engine.dispose()


def test_from_file_json(tmp_path):
    import json

    config_path = tmp_path / "db.json"
    config_path.write_text(json.dumps({"url": f"sqlite:///{tmp_path / 'from_file.db'}"}))
    store = SqlStorage.from_file(str(config_path))
    try:
        store.save(_event(id="from-file-1"))
        assert store.get("from-file-1") is not None
    finally:
        store.close()


@pytest.mark.real_server
def test_summary_groups_errors_by_actor_on_real_postgres():
    """``summary()`` selected ``coalesce(actor_label, <bind>)`` and grouped by a
    second ``coalesce(actor_label, <bind>)``; Postgres cannot match the two
    bound literals and raised GroupingError, so the dashboard Overview failed
    on Postgres while SQLite (which is lenient) passed."""
    url = os.environ.get("JSCOUP_TEST_PG_URL")
    if not url:
        pytest.skip("set JSCOUP_TEST_PG_URL to a real Postgres to run this")

    import uuid

    import sqlalchemy as sa

    # psycopg (v3) sends bound literals to the server as $1/$2, which is what
    # exposed the bug; psycopg2 interpolates them client-side and hides it.
    pytest.importorskip("psycopg")
    url = url.replace("+psycopg2", "+psycopg")

    schema = f"jscoup_sum_{uuid.uuid4().hex[:8]}"
    store = SqlStorage(url, schema=schema)
    try:
        store.save(_event(id="a1", actor=Actor(subject="u1", label="alice", token_fingerprint="t1")))
        store.save(_event(id="a2", actor=Actor(subject="u1", label="alice", token_fingerprint="t1")))
        store.save(_event(id="a3", actor=None))

        summary = store.summary()

        by_actor = {row["actor"]: row["count"] for row in summary["by_actor"]}
        assert by_actor == {"alice": 2, "anonymous": 1}
    finally:
        store.close()
        with sa.create_engine(url).begin() as conn:
            conn.execute(sa.text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
