# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Regression tests for the second-round remediation architecture review
(JSCOUP_Detailed_Remediation_Architecture.docx, findings F01-F18).

Covers Change-Set A ("immediate boundaries"): F01 (persistence privacy),
F02 (destination policy / SSRF), F03 (config file security), F07 (capture
lifecycle under cancellation). F05 (gateway method/access unification) and
F10 (healthcheck safety) are covered directly in test_gateway_routes.py and
test_healthcheck.py instead, next to the existing tests they modify.
"""

from __future__ import annotations

import asyncio
import io
import json
import os
import threading
import time

import pytest

from jscoup import JSCoup, MemoryStorage
from jscoup.redaction import Redactor

try:
    import pydantic as _pydantic_for_tests

    class _OrderBody(_pydantic_for_tests.BaseModel):
        """Module-level on purpose: typing.get_type_hints() (used by
        registry.py's FastAPI discovery to resolve a stringified annotation
        under `from __future__ import annotations`) looks a name up in the
        endpoint function's module globals — a class nested inside the test
        function itself would never be found there, regardless of where the
        endpoint function that references it is defined."""

        item: str
except ImportError:
    _OrderBody = None


# --------------------------------------------------------------------------- #
# F01 — persistence privacy boundary
# --------------------------------------------------------------------------- #


def test_is_sensitive_matches_regardless_of_separator_style():
    """'api_key' (the underscore convention almost all Python config uses)
    used to never match the extremely common real-world header
    'X-API-Key' — only the hyphen differed."""
    r = Redactor(["api_key", "auth_token"])
    assert r.is_sensitive("X-Api-Key") is True
    assert r.is_sensitive("x-api-key") is True
    assert r.is_sensitive("X-Auth-Token") is True
    assert r.is_sensitive("apiKey") is True
    assert r.is_sensitive("unrelated_header") is False


def test_scrub_headers_masks_x_api_key():
    r = Redactor(["api_key"])
    out = r.scrub_headers({"X-Api-Key": "sk_live_abc123", "X-Client": "web"})
    assert out["X-Api-Key"] == r.mask
    assert out["X-Client"] == "web"


def test_stdout_capture_is_redacted():
    bl = JSCoup("t", storage=MemoryStorage(), capture_success=True, capture_print=True)
    with bl.capture(kind="service", name="job") as ctx:
        ctx.stdout_text = 'password: "hunter2"\n'

    event = bl.storage.list()[0]
    assert "hunter2" not in event.stdout_capture


def test_actor_claims_are_redacted_and_original_actor_is_not_mutated():
    from jscoup.models import Actor

    bl = JSCoup("t", storage=MemoryStorage(), capture_success=True)
    live_actor = Actor(subject="u1", claims={"password": "hunter2", "role": "admin"})
    with bl.capture(kind="service", name="job", actor=live_actor):
        pass

    event = bl.storage.list()[0]
    assert event.actor.claims["password"] == bl.config.mask
    assert event.actor.claims["role"] == "admin"
    # the live Actor object handed in by the caller must not be mutated
    assert live_actor.claims["password"] == "hunter2"


def test_meta_kwargs_are_redacted():
    bl = JSCoup("t", storage=MemoryStorage(), capture_success=True)
    with bl.capture(kind="service", name="job", api_key="sk_live_abc123"):
        pass

    event = bl.storage.list()[0]
    assert event.meta["api_key"] == bl.config.mask


def test_headers_body_response_set_directly_on_ctx_are_still_scrubbed():
    """A bare capture() block that sets these fields itself (not through a
    framework integration's own scrub_headers/scrub_body call) must not be
    able to bypass redaction just by not going through that layer."""
    bl = JSCoup("t", storage=MemoryStorage(), capture_success=True)
    with bl.capture(kind="http", name="job") as ctx:
        ctx.headers = {"Authorization": "Bearer sk_live_abc123"}
        ctx.body_preview = 'password="hunter2"'
        ctx.response_preview = 'token="abc.def.ghi"'

    event = bl.storage.list()[0]
    assert event.headers["Authorization"] == bl.config.mask
    assert "hunter2" not in event.body_preview
    assert "abc.def.ghi" not in event.response_preview


def test_sql_text_and_error_are_scrubbed():
    """Pattern-based scrubbing (the only tool available for free-form SQL
    text/driver error strings, which have no key name to match on) catches
    a value next to a recognizable keyword or in a recognizable shape (a
    JWT, a card number) — it can't catch an arbitrary secret with neither.
    That's an inherent limitation, documented in README.md's safety notes,
    not something this test pretends to fully close."""
    from jscoup import dbwatch
    from jscoup.context import CaptureContext

    ctx = CaptureContext(kind="service", name="job")
    with ctx:
        dbwatch.emit_query(
            'UPDATE users SET password = "hunter2" WHERE id = 1',
            error='IntegrityError: password="hunter2" violates check constraint',
        )
    query = ctx.queries[0]
    assert "hunter2" not in query.sql
    assert "hunter2" not in query.error


def test_repr_failing_on_a_successful_return_value_does_not_crash_the_caller():
    """A returned object with a broken __repr__ must not turn a successful
    call into a raised exception."""

    class Broken:
        def __repr__(self):
            raise RuntimeError("no repr for you")

    bl = JSCoup("t", storage=MemoryStorage(), capture_success=True)

    @bl.watch(kind="service", name="returns_broken")
    def returns_broken():
        return Broken()

    result = returns_broken()  # must not raise
    assert isinstance(result, Broken)
    event = bl.storage.list()[0]
    assert "repr() failed" in event.result_preview


# --------------------------------------------------------------------------- #
# F02 — destination policy / SSRF
# --------------------------------------------------------------------------- #


def test_invoke_never_trusts_a_request_derived_fallback_base_url():
    """No base_url configured, none supplied in the request body: this must
    be rejected outright rather than silently falling back to whatever the
    framework integration derived from the incoming request's own Host
    header (the exact bypass this finding reproduced)."""
    bl = JSCoup("t", storage=MemoryStorage(), allow_live_invoke=True, dashboard_local_dev=True)

    @bl.watch(name="svc")
    def svc():
        return "ok"

    # Simulates a framework integration passing a Host-header-derived
    # base_url as `base_url=` to handle() with no explicit field in the body.
    body = json.dumps({"target_id": "service:svc"}).encode()
    res = bl.dashboard.handle(
        "/api/invoke", method="POST", body=body, base_url="http://attacker.example.com",
    )
    assert res.status == 400


def test_invoke_prefers_configured_base_url_over_any_fallback():
    bl = JSCoup(
        "t", storage=MemoryStorage(), allow_live_invoke=True, dashboard_local_dev=True,
        base_url="http://127.0.0.1:9000",
    )

    @bl.watch(name="svc")
    def svc():
        return "ok"

    body = json.dumps({"target_id": "service:svc"}).encode()
    res = bl.dashboard.handle(
        "/api/invoke", method="POST", body=body, base_url="http://attacker.example.com",
    )
    assert res.status == 200


def test_invoke_http_rejects_a_base_url_with_embedded_credentials():
    """Userinfo in a URL (http://user:pass@host/...) is a classic SSRF/
    credential-smuggling vector. This exercises the HTTP replay path
    directly (_invoke_http), which is where this check lives — a "service"
    kind target never reaches it at all."""
    from jscoup.registry import Target

    bl = JSCoup("t", storage=MemoryStorage())
    bl.registry.add(Target(id="http:GET:/x", kind="http", name="x", method="GET", path="/x"))

    result = bl.simulator.invoke("http:GET:/x", base_url="http://user:pass@127.0.0.1:9000")
    assert result["ok"] is False
    assert "credentials" in result["error"]


def test_http_replay_does_not_follow_a_cross_origin_redirect():
    """A redirect handled by the module-level default urllib opener would
    forward the Authorization header (and any other header) to wherever it
    points, with no same-origin check — this proves the replay path uses
    the no-redirect opener instead."""
    import http.server

    hits = {"target": 0}

    class RedirectingHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:1/elsewhere")  # port 1: nothing listens
            self.end_headers()

        def log_message(self, *a):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), RedirectingHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        bl = JSCoup(
            "t", storage=MemoryStorage(), allow_live_invoke=True, dashboard_local_dev=True,
            base_url=f"http://127.0.0.1:{server.server_port}",
        )
        from jscoup.registry import Target

        bl.registry.add(Target(id="http:GET:/redirect", kind="http", name="redirect",
                                method="GET", path="/redirect"))
        body = json.dumps({"target_id": "http:GET:/redirect"}).encode()
        res = bl.dashboard.handle("/api/invoke", method="POST", body=body)
        data = json.loads(res.body)
        # a followed redirect would have tried to connect to port 1 and
        # produced a connection-refused error instead of a clean 302 result
        assert data.get("status_code") == 302
    finally:
        server.shutdown()


# --------------------------------------------------------------------------- #
# F03 — configuration file security
# --------------------------------------------------------------------------- #


def test_config_file_created_with_restrictive_permissions(tmp_path):
    from jscoup import projectconfig

    path = str(tmp_path / "sub" / ".jscoup.config.json")
    projectconfig.load_or_create(path)

    if os.name == "posix":
        mode = os.stat(path).st_mode & 0o777
        assert mode == 0o600


def test_config_save_is_atomic_no_partial_file_left_on_crash(tmp_path, monkeypatch):
    from jscoup import projectconfig

    path = str(tmp_path / ".jscoup.config.json")
    config = projectconfig.ProjectConfig()

    real_fsync = os.fsync

    def failing_fsync(fd):
        raise OSError("disk full")

    monkeypatch.setattr(os, "fsync", failing_fsync)
    with pytest.raises(OSError):
        projectconfig.save(config, path)
    monkeypatch.setattr(os, "fsync", real_fsync)

    assert not os.path.exists(path)  # no half-written file left behind
    leftover_tmp = [f for f in os.listdir(tmp_path) if f.startswith(".jscoup-config-")]
    assert leftover_tmp == []


def test_concurrent_first_run_creation_agrees_on_one_credential_set(tmp_path):
    """Two 'workers' starting at once must not each generate (and use) a
    different admin password."""
    from jscoup import projectconfig

    path = str(tmp_path / ".jscoup.config.json")
    results = []
    lock = threading.Lock()

    def worker():
        cfg = projectconfig.load_or_create(path)
        with lock:
            results.append(cfg.dashboard_password)

    threads = [threading.Thread(target=worker) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(results) == 5  # every worker succeeded — none crashed racing for the lock
    assert len(set(results)) == 1


def test_env_secret_reference_is_resolved(monkeypatch, tmp_path):
    from jscoup import projectconfig

    monkeypatch.setenv("JSCOUP_TEST_PASSWORD", "real-secret-value")
    path = tmp_path / "db.json"
    path.write_text(json.dumps({"dashboard_password": "env:JSCOUP_TEST_PASSWORD"}))

    config = projectconfig.ProjectConfig.from_dict(json.loads(path.read_text()))
    assert config.dashboard_password == "real-secret-value"


def test_features_live_tester_maps_to_allow_live_invoke(tmp_path):
    """features.live_tester=True in the config file used to be a silent
    no-op — there is no JSCoupConfig.live_tester field to receive it."""
    from jscoup import projectconfig

    path = str(tmp_path / ".jscoup.config.json")
    config = projectconfig.load_or_create(path)
    config.features["live_tester"] = True
    projectconfig.save(config, path)

    bl = JSCoup.from_config_file(path=path)
    assert bl.config.allow_live_invoke is True


def test_from_config_file_accepts_a_storage_override_without_crashing(tmp_path):
    """storage= in overrides used to raise 'got multiple values for
    argument storage' because it was passed to the constructor twice."""
    path = str(tmp_path / ".jscoup.config.json")
    custom_storage = MemoryStorage()

    # encryption_key=None: a freshly created project config auto-generates
    # one (when `cryptography` is installed), which would otherwise wrap
    # custom_storage in EncryptingStorage — a real, separate behavior this
    # test isn't the one to pin.
    bl = JSCoup.from_config_file(path=path, storage=custom_storage, encryption_key=None)
    assert bl.storage is custom_storage


# --------------------------------------------------------------------------- #
# F07 — capture lifecycle under cancellation
# --------------------------------------------------------------------------- #


def test_watch_async_cancellation_still_closes_and_records_the_context():
    from jscoup.context import all_contexts

    bl = JSCoup("t", storage=MemoryStorage(), capture_success=True)

    @bl.watch(kind="service", name="cancellable")
    async def cancellable():
        await asyncio.sleep(10)

    async def run():
        task = asyncio.ensure_future(cancellable())
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(run())

    assert all_contexts() == ()
    event = bl.storage.list()[0]
    assert event.status == "error"
    assert event.error_type == "CancelledError"


def test_watch_async_reraise_false_still_propagates_cancellation():
    """reraise=False intentionally swallows an ordinary application
    exception — it must never also swallow a cancellation."""
    bl = JSCoup("t", storage=MemoryStorage())

    @bl.watch(kind="service", name="cancellable2", reraise=False, fallback="fallback-value")
    async def cancellable():
        await asyncio.sleep(10)

    async def run():
        task = asyncio.ensure_future(cancellable())
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(run())  # must raise CancelledError out of the gather, not return "fallback-value"


# --------------------------------------------------------------------------- #
# F04 — gateway authorization authoritative across instances/workers
# --------------------------------------------------------------------------- #


def test_revocation_is_immediately_visible_to_a_second_gateway_store_instance(tmp_path):
    """Two GatewayStore instances sharing one database file (modelling two
    worker processes behind one server) used to disagree: only the instance
    that called revoke() ever refreshed its own in-memory cache, so the
    other kept authenticating the revoked token indefinitely."""
    from jscoup.gateway import GatewayStore

    db_path = str(tmp_path / "gateway.db")
    store_a = GatewayStore(db_path)
    store_b = GatewayStore(db_path)

    user = store_a.create_user("alice", "alice", "pw", allowed_target_ids="*")
    session = store_a.login("alice", "pw")
    token = session["token"]

    # store_b never called create_user/login itself — it must still see the
    # session as valid, reading straight from the shared database.
    assert store_b.authenticate(token) is not None

    store_a.revoke(user.id)

    # store_b must see the revocation immediately, with no reload of its own.
    assert store_b.authenticate(token) is None


def test_public_target_toggle_is_immediately_visible_to_a_second_instance(tmp_path):
    from jscoup.gateway import GatewayStore

    db_path = str(tmp_path / "gateway.db")
    store_a = GatewayStore(db_path)
    store_b = GatewayStore(db_path)

    assert store_b.is_public("service:x") is False
    store_a.set_public("service:x", True)
    assert store_b.is_public("service:x") is True
    store_a.set_public("service:x", False)
    assert store_b.is_public("service:x") is False


def test_new_login_is_immediately_visible_to_a_second_instance(tmp_path):
    from jscoup.gateway import GatewayStore

    db_path = str(tmp_path / "gateway.db")
    store_a = GatewayStore(db_path)
    store_b = GatewayStore(db_path)

    store_a.create_user("bob", "bob", "pw", allowed_target_ids="*")
    session = store_b.login("bob", "pw")  # store_b never created this user itself
    assert session is not None


# --------------------------------------------------------------------------- #
# F06 — revocable admin dashboard sessions
# --------------------------------------------------------------------------- #


def _login_admin(bl, username="admin", password="s3cret-pass"):
    res = bl.dashboard.handle(
        "/api/login", method="POST",
        body=json.dumps({"username": username, "password": password}).encode(),
    )
    set_cookie = (res.headers or {}).get("Set-Cookie", "")
    return {"Cookie": set_cookie.split(";", 1)[0]}


def test_logout_immediately_revokes_the_session_a_copied_cookie_stops_working(tmp_path):
    """A copied cookie (an XSS read, a shared machine, a proxy access log)
    must stop authenticating the moment the legitimate user logs out — the
    old stateless-HMAC design had no server-side state to revoke, so it
    stayed valid until its own embedded expiry regardless of logout."""
    bl = JSCoup(
        "t", storage=MemoryStorage(), dashboard_username="admin", dashboard_password="s3cret-pass",
        dashboard_session_db_path=str(tmp_path / "sessions.db"),
    )
    session = _login_admin(bl)
    assert bl.dashboard.handle("/api/health", headers=session).status == 200

    bl.dashboard.handle("/api/logout", method="POST", headers=session)

    assert bl.dashboard.handle("/api/health", headers=session).status == 401


def test_sessions_are_shared_across_two_jscoup_instances_pointed_at_the_same_db(tmp_path):
    """A session created on one worker process must authenticate on
    another — the previous design needed the same random signing key on
    every worker (never guaranteed unless set explicitly); this needs only
    the same session database file."""
    session_db = str(tmp_path / "sessions.db")
    bl_a = JSCoup(
        "t", storage=MemoryStorage(), dashboard_username="admin", dashboard_password="s3cret-pass",
        dashboard_session_db_path=session_db,
    )
    bl_b = JSCoup(
        "t", storage=MemoryStorage(), dashboard_username="admin", dashboard_password="s3cret-pass",
        dashboard_session_db_path=session_db,
    )

    session = _login_admin(bl_a)
    # bl_b never issued this session itself — it must still accept it.
    assert bl_b.dashboard.handle("/api/health", headers=session).status == 200

    bl_b.dashboard.handle("/api/logout", method="POST", headers=session)
    # revoked via bl_b — bl_a must see that immediately too.
    assert bl_a.dashboard.handle("/api/health", headers=session).status == 401


def test_expired_session_is_rejected(tmp_path):
    from jscoup.dashboard.sessions import SessionStore

    store = SessionStore(str(tmp_path / "sessions.db"))
    token = store.create("admin", ttl_seconds=-1)
    assert store.verify(token) is None


def test_revoke_all_invalidates_every_session(tmp_path):
    from jscoup.dashboard.sessions import SessionStore

    store = SessionStore(str(tmp_path / "sessions.db"))
    t1 = store.create("admin", ttl_seconds=3600)
    t2 = store.create("admin", ttl_seconds=3600)
    store.revoke_all()
    assert store.verify(t1) is None
    assert store.verify(t2) is None


# --------------------------------------------------------------------------- #
# F13 — diagnostic rules specific and auditable
# --------------------------------------------------------------------------- #


def _db_diagnosis(error_type, error_module, message, exception=None):
    from jscoup.analyzers.base import AnalysisInput
    from jscoup.analyzers.database import DatabaseAnalyzer

    exc = exception
    if exc is None:
        exc = type(error_type, (Exception,), {})(message)
        exc.__class__.__module__ = error_module
    data = AnalysisInput(exception=exc, error_type=error_type, error_module=error_module, error_message=message)
    return DatabaseAnalyzer().analyze(data)


def test_undefined_column_is_not_misclassified_as_missing_table():
    d = _db_diagnosis("UndefinedColumn", "psycopg2.errors", 'column "foo" of relation "bar" does not exist')
    assert d is not None
    assert d.subtype == "missing_column"


def test_undefined_table_still_classifies_as_missing_table():
    d = _db_diagnosis("UndefinedTable", "psycopg2.errors", 'relation "bar" does not exist')
    assert d is not None
    assert d.subtype == "missing_table"


def test_plain_builtin_timeout_error_is_not_treated_as_a_database_failure():
    """A bare TimeoutError (raised constantly for ordinary network/queue
    timeouts) must not be claimed by DatabaseAnalyzer just because
    SQLAlchemy happens to use the same class name for a pool timeout —
    NetworkAnalyzer is the one that should classify it instead."""
    d = _db_diagnosis("TimeoutError", "builtins", "The read operation timed out")
    assert d is None


def test_sqlalchemy_pool_timeout_is_still_classified_as_a_database_failure():
    d = _db_diagnosis("TimeoutError", "sqlalchemy.pool.impl", "QueuePool limit of size 5 overflow 10 reached")
    assert d is not None
    assert d.subtype == "pool_exhausted"


def test_full_engine_routes_a_real_timeout_error_to_network_not_database():
    from jscoup.analyzers import AnalyzerEngine
    from jscoup.analyzers.base import AnalysisInput

    exc = TimeoutError("The read operation timed out")
    data = AnalysisInput(exception=exc, error_type="TimeoutError", error_module="builtins", error_message=str(exc))
    diagnosis = AnalyzerEngine().analyze(data)
    assert diagnosis is not None
    assert diagnosis.category == "network"


# --------------------------------------------------------------------------- #
# F15 — one storage contract (issue-grouping consistency)
# --------------------------------------------------------------------------- #


def test_sql_storage_groups_issues_by_fingerprint_alone(tmp_path):
    """Two events sharing one fingerprint but with a different error_message
    (a driver message quoting a different literal value each time) used to
    become two separate 'issues' in SqlStorage instead of one occurring
    twice — the same bug counted twice, undercounting the real total."""
    pytest.importorskip("sqlalchemy")
    from jscoup.models import EventRecord
    from jscoup.storage.sql import SqlStorage

    storage = SqlStorage(f"sqlite:///{tmp_path / 'events.db'}")
    try:
        storage.save(EventRecord(id="a", name="job", status="error", fingerprint="fp1",
                                  error_type="ValueError", error_message="first message", ts=time.time()))
        storage.save(EventRecord(id="b", name="job", status="error", fingerprint="fp1",
                                  error_type="ValueError", error_message="second message", ts=time.time() + 1))
        issues = storage.issues()
        assert len(issues) == 1
        assert issues[0]["count"] == 2
        assert issues[0]["error_message"] == "second message"  # the most recent occurrence
    finally:
        storage.close()


def test_sql_storage_issue_grouping_matches_memory_and_sqlite(tmp_path):
    pytest.importorskip("sqlalchemy")
    from jscoup.models import EventRecord
    from jscoup.storage.memory import MemoryStorage
    from jscoup.storage.sql import SqlStorage
    from jscoup.storage.sqlite import SQLiteStorage

    events = [
        EventRecord(id="a", name="job", status="error", fingerprint="fp1",
                    error_type="ValueError", error_message="msg a", ts=time.time()),
        EventRecord(id="b", name="job", status="error", fingerprint="fp1",
                    error_type="ValueError", error_message="msg b", ts=time.time() + 1),
        EventRecord(id="c", name="job", status="error", fingerprint="fp2",
                    error_type="KeyError", error_message="msg c", ts=time.time() + 2),
    ]

    mem = MemoryStorage()
    sq = SQLiteStorage(db_path=str(tmp_path / "sqlite.db"))
    sql_storage = SqlStorage(f"sqlite:///{tmp_path / 'sql.db'}")
    try:
        for e in events:
            mem.save(e)
            sq.save(e)
            sql_storage.save(e)

        counts = {
            "memory": sorted(i["count"] for i in mem.issues()),
            "sqlite": sorted(i["count"] for i in sq.issues()),
            "sql": sorted(i["count"] for i in sql_storage.issues()),
        }
        assert counts["memory"] == counts["sqlite"] == counts["sql"] == [1, 2]
    finally:
        sq.close()
        sql_storage.close()


# --------------------------------------------------------------------------- #
# F12 — replay requests built from a complete target schema
# --------------------------------------------------------------------------- #


def test_typed_flask_path_parameter_is_substituted_correctly():
    """Flask writes a typed path segment as <converter:name> (e.g.
    <int:item_id>) — name second. simulator.py used to re-derive path
    parameter names with its own regex that assumed name-first ordering,
    capturing "int" instead of "item_id": the real value never got
    substituted into the path and was appended as a query string instead."""
    flask = pytest.importorskip("flask")
    werkzeug_serving = pytest.importorskip("werkzeug.serving")
    from jscoup import JSCoup, MemoryStorage

    app = flask.Flask(__name__)

    @app.get("/items/<int:item_id>")
    def get_item(item_id):
        return flask.jsonify(item_id=item_id, type=type(item_id).__name__)

    bl = JSCoup("t", storage=MemoryStorage(), dashboard_local_dev=True, allow_live_invoke=True)
    bl.install(app)

    server = werkzeug_serving.make_server("127.0.0.1", 0, app)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = bl.simulator.invoke(
            "http:GET:/items/<int:item_id>", params={"item_id": "42"},
            base_url=f"http://127.0.0.1:{port}",
        )
        assert result["ok"] is True
        assert result["url"] == f"http://127.0.0.1:{port}/items/42"
        assert result["response"] == {"item_id": 42, "type": "int"}
    finally:
        server.shutdown()


def test_fastapi_discovery_resolves_stringified_annotations():
    """`from __future__ import annotations` (a common, often-recommended
    pattern in the *monitored app's own* code) makes every annotation in
    that module a plain string at runtime — inspect.signature() alone never
    resolves it back to the real class, so a Pydantic body model showed up
    as one opaque param named after its argument instead of being expanded
    into its real fields. This test file itself uses that same future
    import, so it doubles as its own reproduction."""
    fastapi = pytest.importorskip("fastapi")
    pytest.importorskip("pydantic")
    if _OrderBody is None:
        pytest.skip("pydantic not installed")
    from jscoup import JSCoup, MemoryStorage

    app = fastapi.FastAPI()

    @app.post("/orders2")
    def create_order2(body: _OrderBody, notify: bool = False):
        return {"item": body.item, "notify": notify}

    bl = JSCoup("t", storage=MemoryStorage(), dashboard_local_dev=True)
    bl.install(app)

    target = bl.registry.get("http:POST:/orders2")
    names = {p.name: p.location for p in target.params}
    assert names == {"item": "body", "notify": "query"}


def test_fastapi_query_parameter_is_not_merged_into_the_json_body():
    """A FastAPI route with both a Pydantic body model and a plain query
    parameter used to have that query parameter dumped into the JSON body
    too, since replay only ever split params by HTTP method, never by each
    parameter's own declared location — the server received its own
    default for that field instead of the caller's real value."""
    fastapi = pytest.importorskip("fastapi")
    pytest.importorskip("pydantic")
    uvicorn = pytest.importorskip("uvicorn")
    if _OrderBody is None:
        pytest.skip("pydantic not installed")
    from jscoup import JSCoup, MemoryStorage

    app = fastapi.FastAPI()

    @app.post("/orders")
    def create_order(body: _OrderBody, notify: bool = False):
        return {"item": body.item, "notify": notify}

    bl = JSCoup("t", storage=MemoryStorage(), dashboard_local_dev=True, allow_live_invoke=True)
    bl.install(app)

    config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 5
    while not getattr(server, "started", False) and time.time() < deadline:
        time.sleep(0.05)
    port = server.servers[0].sockets[0].getsockname()[1]
    try:
        result = bl.simulator.invoke(
            "http:POST:/orders", params={"item": "widget", "notify": True},
            base_url=f"http://127.0.0.1:{port}",
        )
        assert result["ok"] is True, result["response"]
        assert result["request_body"] == {"item": "widget"}
        assert "notify=True" in result["url"]
        assert result["response"] == {"item": "widget", "notify": True}
    finally:
        server.should_exit = True
        thread.join(timeout=5)


# --------------------------------------------------------------------------- #
# F11 — encrypted records: legacy format still readable
# --------------------------------------------------------------------------- #


def test_legacy_per_value_encrypted_headers_and_params_still_decrypt(tmp_path):
    """Records written before this module encrypted a whole container as
    one blob had each sensitive string value individually prefixed with
    enc: — the new container-format reader used to treat any dict lacking
    the container marker as 'never encrypted' and return it unchanged,
    silently leaving raw ciphertext mixed into otherwise-plaintext data."""
    crypto = pytest.importorskip("jscoup.crypto")
    from jscoup.models import EventRecord

    key = crypto.generate_key()
    event = EventRecord(id="legacy-1", name="job")
    event.headers = {
        "X-Client-Note": crypto.encrypt_text("internal routing detail", key),
        "X-Public": "not-secret",
    }
    event.params = {
        "account_number": crypto.encrypt_text("AB1234567", key),
        "page": 2,
    }

    crypto.decrypt_event_fields(event, key)
    assert event.headers == {"X-Client-Note": "internal routing detail", "X-Public": "not-secret"}
    assert event.params == {"account_number": "AB1234567", "page": 2}


def test_legacy_and_current_format_both_readable_through_encrypting_storage(tmp_path):
    crypto = pytest.importorskip("jscoup.crypto")
    from jscoup.models import EventRecord
    from jscoup.storage.memory import MemoryStorage as _MemoryStorage

    key = crypto.generate_key()
    inner = _MemoryStorage()

    # A record written the "current" way, via the real save() path.
    storage = crypto.EncryptingStorage(inner, key)
    storage.save(EventRecord(id="current-1", name="job", params={"note": "hello"}))

    # A record written the way an earlier version of this module would
    # have, injected directly into the inner backend (save() always writes
    # the newest format now, so this simulates data from before this fix).
    legacy_event = EventRecord(id="legacy-1", name="job")
    legacy_event.params = {"secret_field": crypto.encrypt_text("legacy value", key)}
    inner.save(legacy_event)

    assert storage.get("current-1").params == {"note": "hello"}
    assert storage.get("legacy-1").params == {"secret_field": "legacy value"}


# --------------------------------------------------------------------------- #
# F08 — genuinely asynchronous invocation
# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
# F17 — dashboard input validation
# --------------------------------------------------------------------------- #


def test_timeline_rejects_zero_buckets_with_a_400_instead_of_crashing():
    bl = JSCoup("t", storage=MemoryStorage(), dashboard_local_dev=True)
    res = bl.dashboard.handle("/api/timeline", query={"buckets": "0"})
    assert res.status == 400


def test_timeline_rejects_non_numeric_buckets():
    bl = JSCoup("t", storage=MemoryStorage(), dashboard_local_dev=True)
    res = bl.dashboard.handle("/api/timeline", query={"buckets": "abc"})
    assert res.status == 400


def test_timeline_accepts_valid_buckets():
    bl = JSCoup("t", storage=MemoryStorage(), dashboard_local_dev=True)
    res = bl.dashboard.handle("/api/timeline", query={"buckets": "10", "window": "600"})
    assert res.status == 200
    assert len(json.loads(res.body)["buckets"]) == 10


def test_events_rejects_negative_limit_and_offset():
    bl = JSCoup("t", storage=MemoryStorage(), dashboard_local_dev=True)
    assert bl.dashboard.handle("/api/events", query={"limit": "-1"}).status == 400
    assert bl.dashboard.handle("/api/events", query={"offset": "-1"}).status == 400
    assert bl.dashboard.handle("/api/events", query={"limit": "not-a-number"}).status == 400


def test_issues_rejects_non_numeric_limit():
    bl = JSCoup("t", storage=MemoryStorage(), dashboard_local_dev=True)
    assert bl.dashboard.handle("/api/issues", query={"limit": "abc"}).status == 400


# --------------------------------------------------------------------------- #
# F14 — SQL instrumentation lifecycle (idempotent install)
# --------------------------------------------------------------------------- #


def test_instrument_sqlalchemy_twice_does_not_duplicate_query_records():
    sa = pytest.importorskip("sqlalchemy")
    from jscoup.context import CaptureContext
    from jscoup.dbwatch import instrument_sqlalchemy, uninstrument_sqlalchemy

    engine = sa.create_engine("sqlite:///:memory:")
    try:
        instrument_sqlalchemy(engine)
        instrument_sqlalchemy(engine)  # a second, defensive call

        ctx = CaptureContext(kind="service", name="job")
        with ctx:
            with engine.connect() as conn:
                conn.execute(sa.text("SELECT 1"))

        assert len(ctx.queries) == 1
    finally:
        uninstrument_sqlalchemy(engine)
        engine.dispose()


def test_uninstrument_sqlalchemy_stops_recording():
    sa = pytest.importorskip("sqlalchemy")
    from jscoup.context import CaptureContext
    from jscoup.dbwatch import instrument_sqlalchemy, uninstrument_sqlalchemy

    engine = sa.create_engine("sqlite:///:memory:")
    try:
        instrument_sqlalchemy(engine)
        uninstrument_sqlalchemy(engine)

        ctx = CaptureContext(kind="service", name="job")
        with ctx:
            with engine.connect() as conn:
                conn.execute(sa.text("SELECT 1"))

        assert len(ctx.queries) == 0
    finally:
        engine.dispose()


# --------------------------------------------------------------------------- #
# F18 — release claims traceable to build artifacts
# --------------------------------------------------------------------------- #


def test_dunder_version_matches_pyproject_toml():
    """Package metadata and jscoup.__version__ drifted apart once already
    (declared 2.0.0, reported 1.2.0) — this pins them together so it can't
    happen silently again."""
    import re

    import jscoup

    pyproject_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "pyproject.toml")
    with open(pyproject_path, "r", encoding="utf-8") as f:
        text = f.read()
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    assert match is not None, "no version = \"...\" line found in pyproject.toml"
    assert jscoup.__version__ == match.group(1)


def test_watch_sync_reraise_false_does_not_swallow_keyboard_interrupt():
    bl = JSCoup("t", storage=MemoryStorage())

    @bl.watch(kind="service", name="interruptible", reraise=False, fallback="fallback-value")
    def interruptible():
        raise KeyboardInterrupt()

    with pytest.raises(KeyboardInterrupt):
        interruptible()

    event = bl.storage.list()[0]
    assert event.error_type == "KeyboardInterrupt"
