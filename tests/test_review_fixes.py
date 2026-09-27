# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Targeted regressions for the external code review of JSCOUP: one test per
confirmed finding, reproducing the original defect and pinning the fix.

Findings 1 and most of 4/6/7 already have their own coverage added directly
in test_dashboard_auth.py/test_core.py; this file covers the ones that had
no natural home yet: query_string/tags/breadcrumb/SQL-param redaction
(2), the base_url SSRF gate (5), ASGI task cancellation (7b), the
instrumentation side effects in dbwatch (8), and duplicate query rows on a
repeated save (9).
"""

from __future__ import annotations

import asyncio
import json

import pytest

from jscoup import JSCoup, MemoryStorage
from jscoup.storage.sqlite import SQLiteStorage


# --------------------------------------------------------------------------- #
# Finding 1 — allow_live_invoke defaults to off
# --------------------------------------------------------------------------- #


def test_allow_live_invoke_defaults_to_false():
    bl = JSCoup("t", storage=MemoryStorage(), dashboard_local_dev=True)
    assert bl.config.allow_live_invoke is False
    res = bl.dashboard.handle("/api/invoke", method="POST", body=b'{"target_id":"x"}')
    assert res.status == 403


# --------------------------------------------------------------------------- #
# Finding 4 — X-Forwarded-For is only trusted when explicitly configured
# --------------------------------------------------------------------------- #


def test_flask_ignores_forwarded_for_header_by_default():
    flask = pytest.importorskip("flask")
    app = flask.Flask(__name__)
    bl = JSCoup("t", storage=MemoryStorage(), capture_success=True, dashboard_local_dev=True)
    bl.install(app)

    @app.route("/ping")
    def ping():
        return "pong"

    client = app.test_client()
    client.get("/ping", headers={"X-Forwarded-For": "203.0.113.99"})
    event = bl.storage.list()[0]
    assert event.client_ip != "203.0.113.99"


def test_flask_trusts_forwarded_for_header_when_explicitly_enabled():
    flask = pytest.importorskip("flask")
    app = flask.Flask(__name__)
    bl = JSCoup(
        "t", storage=MemoryStorage(), capture_success=True, dashboard_local_dev=True,
        trust_proxy_headers=True,
    )
    bl.install(app)

    @app.route("/ping")
    def ping():
        return "pong"

    client = app.test_client()
    client.get("/ping", headers={"X-Forwarded-For": "203.0.113.99"})
    event = bl.storage.list()[0]
    assert event.client_ip == "203.0.113.99"


# --------------------------------------------------------------------------- #
# Finding 6 — a failing before_store hook must drop the event, not store it
# unsanitized
# --------------------------------------------------------------------------- #


def test_failing_before_store_hook_drops_the_event_instead_of_storing_it_raw():
    def broken_hook(event):
        raise RuntimeError("sanitizer bug")

    bl = JSCoup(
        "t", storage=MemoryStorage(), capture_success=True, dashboard_local_dev=True,
        before_store=broken_hook,
    )
    with bl.capture(kind="service", name="job") as ctx:
        ctx.body_preview = "should never be persisted"

    assert bl.storage.list() == []
    assert bl._before_store_failures == 1
    health = json.loads(bl.dashboard.handle("/api/health").body)
    assert health["before_store_failures"] == 1


# --------------------------------------------------------------------------- #
# Finding 7a — enabled=False must also stop begin()/end() (every framework's
# own middleware), not just capture()
# --------------------------------------------------------------------------- #


def test_disabling_capture_also_stops_begin_end_used_by_middlewares():
    bl = JSCoup("t", storage=MemoryStorage(), capture_success=True, enabled=False, dashboard_local_dev=True)
    ctx = bl.begin(kind="http", name="req")
    bl.end(ctx)
    assert bl.storage.list() == []


# --------------------------------------------------------------------------- #
# Finding 2 — incomplete redaction
# --------------------------------------------------------------------------- #


def test_query_string_sensitive_values_are_masked():
    bl = JSCoup("t", storage=MemoryStorage(), capture_success=True)
    ctx = bl.begin(kind="http", name="req", query_string="token=abc123&page=2")
    bl.end(ctx)

    event = bl.storage.list()[0]
    assert "abc123" not in event.query_string
    assert "page=2" in event.query_string


def test_tags_are_redacted():
    bl = JSCoup("t", storage=MemoryStorage(), capture_success=True)
    with bl.capture(kind="service", name="job", tags={"api_key": "sk-secret-value"}):
        pass

    event = bl.storage.list()[0]
    assert event.tags["api_key"] == bl.config.mask


def test_breadcrumb_data_is_redacted_and_original_is_not_mutated():
    bl = JSCoup("t", storage=MemoryStorage(), capture_success=True)
    with bl.capture(kind="service", name="job") as ctx:
        bl.note("looked up user", password="hunter2")
        live_breadcrumb = ctx.breadcrumbs[0]

    event = bl.storage.list()[0]
    assert event.breadcrumbs[0].data["password"] == bl.config.mask
    # the live context's own breadcrumb object must be untouched — the fix
    # builds a scrubbed copy for storage, it never scrubs in place.
    assert live_breadcrumb.data["password"] == "hunter2"


def test_sql_param_preview_masks_named_secret_params():
    from jscoup import dbwatch
    from jscoup.context import CaptureContext

    ctx = CaptureContext(kind="service", name="job")
    with ctx:
        dbwatch.emit_query(
            "UPDATE users SET password = :password WHERE id = :id",
            params={"password": "hunter2", "id": 1},
        )
    assert len(ctx.queries) == 1
    assert "hunter2" not in ctx.queries[0].params_preview
    assert ctx.queries[0].params_preview == "[redacted]"  # 2.3 privacy contract: omit all bind values


# --------------------------------------------------------------------------- #
# Finding 5 — SSRF via a caller-supplied base_url
# --------------------------------------------------------------------------- #


def test_invoke_rejects_a_base_url_outside_the_allowlist():
    bl = JSCoup(
        "t", storage=MemoryStorage(), allow_live_invoke=True, dashboard_local_dev=True,
        base_url="http://127.0.0.1:9000",
    )

    @bl.watch(name="svc")
    def svc():
        return "ok"

    body = json.dumps({"target_id": "service:svc", "base_url": "http://evil.example.com"}).encode()
    res = bl.dashboard.handle("/api/invoke", method="POST", body=body)
    assert res.status == 400


def test_invoke_allows_the_configured_base_url_and_explicit_allowlist_entries():
    bl = JSCoup(
        "t", storage=MemoryStorage(), allow_live_invoke=True, dashboard_local_dev=True,
        base_url="http://127.0.0.1:9000", allowed_base_urls=["http://127.0.0.1:9100"],
    )

    @bl.watch(name="svc")
    def svc():
        return "ok"

    for allowed in ("http://127.0.0.1:9000", "http://127.0.0.1:9100"):
        body = json.dumps({"target_id": "service:svc", "base_url": allowed}).encode()
        res = bl.dashboard.handle("/api/invoke", method="POST", body=body)
        assert res.status == 200, res.body


# --------------------------------------------------------------------------- #
# Finding 7b — asyncio.CancelledError must still close the capture context
# --------------------------------------------------------------------------- #


def test_asgi_middleware_closes_context_on_task_cancellation():
    from jscoup.integrations.fastapi import JSCoupASGIMiddleware
    from jscoup.context import all_contexts

    bl = JSCoup("t", storage=MemoryStorage(), capture_success=True)

    async def inner_app(scope, receive, send):
        raise asyncio.CancelledError()

    middleware = JSCoupASGIMiddleware(inner_app, bl)
    scope = {"type": "http", "method": "GET", "path": "/slow", "headers": [], "query_string": b""}

    async def receive():
        return {"type": "http.request", "body": b""}

    async def send(message):
        pass

    async def run():
        with pytest.raises(asyncio.CancelledError):
            await middleware(scope, receive, send)

    asyncio.run(run())

    # the context must have been popped, not leaked on the stack forever
    assert all_contexts() == ()
    # and the cancelled request must still have been recorded as an event
    assert bl.storage.list()[0].status == "error"


# --------------------------------------------------------------------------- #
# Finding 8 — instrumentation side effects
# --------------------------------------------------------------------------- #


def test_safe_len_does_not_consume_a_generator():
    from jscoup.dbwatch import _safe_len

    def gen():
        yield 1
        yield 2
        yield 3

    g = gen()
    assert _safe_len(g) == "?"  # a generator has no len() — honest "unknown"
    # and, crucially, it was never materialised to find out:
    assert list(g) == [1, 2, 3]


def test_safe_len_reports_a_real_length_when_available():
    from jscoup.dbwatch import _safe_len

    assert _safe_len([1, 2, 3]) == "3"
    assert _safe_len((1, 2)) == "2"


def test_emit_query_is_a_no_op_with_no_active_context(monkeypatch):
    from jscoup import dbwatch

    called = []
    monkeypatch.setattr(dbwatch, "_caller", lambda: called.append("caller") or "x")
    dbwatch.emit_query("SELECT 1")  # no active CaptureContext anywhere
    assert called == []  # _caller() must not even run — nothing would use its result


# --------------------------------------------------------------------------- #
# Finding 9 — duplicate query rows on a repeated save
# --------------------------------------------------------------------------- #


def test_sqlite_storage_resaving_an_event_does_not_duplicate_its_queries(tmp_path):
    from jscoup.models import EventRecord, QueryRecord

    storage = SQLiteStorage(db_path=str(tmp_path / "events.db"))
    event = EventRecord(
        id="fixed-id", name="job",
        queries=[QueryRecord(sql="SELECT 1"), QueryRecord(sql="SELECT 2")],
    )
    storage.save(event)
    storage.save(event)  # same id, e.g. a status update once the request finishes

    row_count = storage.conn.execute(
        "SELECT COUNT(*) FROM queries WHERE event_id = ?", (event.id,)
    ).fetchone()[0]
    assert row_count == 2


def test_sql_storage_resaving_an_event_does_not_duplicate_its_queries(tmp_path):
    pytest.importorskip("sqlalchemy")
    from jscoup.models import EventRecord, QueryRecord
    from jscoup.storage.sql import SqlStorage

    storage = SqlStorage(f"sqlite:///{tmp_path / 'events.db'}")
    event = EventRecord(
        id="fixed-id", name="job",
        queries=[QueryRecord(sql="SELECT 1"), QueryRecord(sql="SELECT 2")],
    )
    storage.save(event)
    storage.save(event)

    with storage.engine.connect() as conn:
        count = conn.execute(
            storage._sa.select(storage._sa.func.count()).select_from(storage.queries).where(
                storage.queries.c.event_id == event.id
            )
        ).scalar_one()
    assert count == 2
