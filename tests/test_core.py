# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Unit tests for the JSCoup core: capture, analysis, storage, identity."""

import sqlite3
import sys
import time
import types

import pytest

from jscoup import JSCoup, JSCoupConfig, MemoryStorage, SQLiteStorage
from jscoup.analyzers import AnalysisInput, AnalyzerEngine, BaseAnalyzer
from jscoup.identity import decode_jwt_payload, fingerprint_token
from jscoup.redaction import Redactor


@pytest.fixture
def bl():
    # dashboard_local_dev=True: these tests exercise dashboard routes
    # directly without going through a login flow, which is not what they're
    # testing — the auto-generated-admin lockdown itself is covered in
    # tests/test_dashboard_auth.py.
    return JSCoup("test", storage=MemoryStorage(), capture_success=False, dashboard_local_dev=True)


@pytest.fixture
def db(tmp_path):
    path = str(tmp_path / "app.db")
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, age INTEGER);
        CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL
                             REFERENCES users(id), total REAL);
        PRAGMA foreign_keys = ON;
        INSERT INTO users (email, age) VALUES ('a@example.com', 30);
        INSERT INTO users (email, age) VALUES ('b@example.com', NULL);
        """
    )
    conn.commit()
    conn.close()
    return path


def open_db(path):
    from jscoup import connect

    conn = connect(path)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


# --------------------------------------------------------------------------- #
# capture basics
# --------------------------------------------------------------------------- #


def test_capture_records_exception(bl):
    with pytest.raises(ValueError):
        with bl.capture(kind="task", name="job"):
            raise ValueError("boom")
    events = bl.storage.list()
    assert len(events) == 1
    assert events[0].error_type == "ValueError"
    assert events[0].status == "error"
    assert events[0].traceback_text


def test_capture_success_not_stored_by_default(bl):
    with bl.capture(kind="task", name="job"):
        pass
    assert bl.storage.list() == []


def test_capture_success_stored_when_enabled():
    bl = JSCoup("t", storage=MemoryStorage(), capture_success=True)
    with bl.capture(kind="task", name="job"):
        pass
    assert len(bl.storage.list()) == 1


def test_watch_decorator_sync(bl):
    @bl.watch(kind="service", name="divide")
    def divide(a, b):
        return a / b

    assert divide(10, 2) == 5
    with pytest.raises(ZeroDivisionError):
        divide(1, 0)
    events = bl.storage.list()
    assert len(events) == 1
    assert events[0].params == {"a": 1, "b": 0}
    assert events[0].name == "divide"


def test_watch_decorator_can_swallow(bl):
    @bl.watch(reraise=False, fallback={"ok": False})
    def flaky():
        raise RuntimeError("nope")

    assert flaky() == {"ok": False}
    assert bl.storage.list()[0].error_type == "RuntimeError"


def test_watch_decorator_async(bl):
    import asyncio

    @bl.watch(kind="service")
    async def fetch(x):
        raise KeyError("missing")

    with pytest.raises(KeyError):
        asyncio.run(fetch(1))
    assert bl.storage.list()[0].error_type == "KeyError"


def _fake_module(name, **functions):
    """Build a throwaway module object with the given functions "defined" in
    it (their __module__ set to `name`), registered in sys.modules."""
    module = types.ModuleType(name)
    for fname, func in functions.items():
        func.__module__ = name
        func.__name__ = fname
        func.__qualname__ = fname
        setattr(module, fname, func)
    sys.modules[name] = module
    return module


def test_watch_module_wraps_every_defined_function(bl):
    def do_work(x):
        return x * 2

    def _private_helper():
        return "hidden"

    module = _fake_module("_blt_module_a", do_work=do_work, _private_helper=_private_helper)
    try:
        count = bl.watch_module(module)
        assert count == 1  # the underscore-prefixed one is skipped by default
        assert module.do_work(3) == 6  # still callable, transparently wrapped
        ids = {t.id for t in bl.registry.all()}
        assert "service:_blt_module_a.do_work" in ids
    finally:
        del sys.modules["_blt_module_a"]


def test_watch_module_skips_functions_only_imported_not_defined(bl):
    def real_func():
        return 1

    _fake_module("_blt_module_b", real_func=real_func)  # real_func "lives" here
    imported_into = types.ModuleType("_blt_module_c")
    imported_into.real_func = real_func  # merely imported, __module__ still "_blt_module_b"
    sys.modules["_blt_module_c"] = imported_into
    try:
        assert bl.watch_module(imported_into) == 0
    finally:
        del sys.modules["_blt_module_b"]
        del sys.modules["_blt_module_c"]


def test_watch_module_is_idempotent(bl):
    def do_work():
        return 1

    module = _fake_module("_blt_module_d", do_work=do_work)
    try:
        assert bl.watch_module(module) == 1
        assert bl.watch_module(module) == 0  # already wrapped the second time
    finally:
        del sys.modules["_blt_module_d"]


def test_watch_module_captures_exceptions(bl):
    def boom():
        raise ValueError("kaboom")

    module = _fake_module("_blt_module_e", boom=boom)
    try:
        bl.watch_module(module)
        with pytest.raises(ValueError):
            module.boom()
        events = bl.storage.list()
        assert any(e.name == "_blt_module_e.boom" and e.error_type == "ValueError" for e in events)
    finally:
        del sys.modules["_blt_module_e"]


def test_watch_module_recursive_walks_submodules(tmp_path, monkeypatch, bl):
    pkg = tmp_path / "_blt_pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "sub.py").write_text("def helper():\n    return 42\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))
    import importlib

    package = importlib.import_module("_blt_pkg")
    try:
        count = bl.watch_module(package, recursive=True)
        assert count == 1
        sub = importlib.import_module("_blt_pkg.sub")
        assert sub.helper() == 42
        ids = {t.id for t in bl.registry.all()}
        assert "service:_blt_pkg.sub.helper" in ids
    finally:
        for name in list(sys.modules):
            if name == "_blt_pkg" or name.startswith("_blt_pkg."):
                del sys.modules[name]


def test_nested_capture_links_parent(bl):
    with pytest.raises(ValueError):
        with bl.capture(kind="http", name="outer") as outer:
            with bl.capture(kind="service", name="inner"):
                raise ValueError("inner failed")
    events = {e.name: e for e in bl.storage.list()}
    assert events["inner"].parent_id == outer.id


def test_breadcrumbs_are_recorded(bl):
    with pytest.raises(RuntimeError):
        with bl.capture(name="job"):
            bl.note("step one", category="flow", step=1)
            bl.note("step two", category="flow", step=2)
            raise RuntimeError("late failure")
    crumbs = bl.storage.list()[0].breadcrumbs
    assert [c.message for c in crumbs] == ["step one", "step two"]


def test_record_exception_outside_capture(bl):
    try:
        raise TypeError("standalone")
    except TypeError as exc:
        bl.record_exception(exc, name="manual")
    assert bl.storage.list()[0].name == "manual"


def test_ignored_exceptions_are_dropped():
    bl = JSCoup("t", storage=MemoryStorage(), ignored_exceptions=["KeyError"])
    with pytest.raises(KeyError):
        with bl.capture(name="job"):
            raise KeyError("x")
    assert bl.storage.list() == []


# --------------------------------------------------------------------------- #
# database analysis
# --------------------------------------------------------------------------- #


def test_unique_violation_is_diagnosed(bl, db):
    with pytest.raises(sqlite3.IntegrityError):
        with bl.capture(name="create-user"):
            conn = open_db(db)
            conn.execute("INSERT INTO users (email, age) VALUES (?, ?)", ("a@example.com", 20))
            conn.commit()
    event = bl.storage.list()[0]
    assert event.category == "database"
    assert event.diagnosis.subtype == "unique_violation"
    assert event.query_count == 2  # PRAGMA + INSERT
    assert any(q.error for q in event.queries)
    assert "sql" in event.diagnosis.evidence


def test_foreign_key_violation_is_diagnosed(bl, db):
    with pytest.raises(sqlite3.IntegrityError):
        with bl.capture(name="create-order"):
            conn = open_db(db)
            conn.execute("INSERT INTO orders (user_id, total) VALUES (?, ?)", (9999, 10))
            conn.commit()
    diag = bl.storage.list()[0].diagnosis
    assert diag.subtype == "foreign_key_violation"
    assert diag.suggested_fixes


def test_missing_table_is_schema_drift(bl, db):
    with pytest.raises(sqlite3.OperationalError):
        with bl.capture(name="report"):
            open_db(db).execute("SELECT * FROM customer_stats").fetchall()
    diag = bl.storage.list()[0].diagnosis
    assert diag.subtype == "missing_table"
    assert diag.severity == "critical"
    assert diag.evidence.get("table") == "customer_stats"


def test_not_null_violation(bl, db):
    with pytest.raises(sqlite3.IntegrityError):
        with bl.capture(name="create-user"):
            conn = open_db(db)
            conn.execute("INSERT INTO users (email) VALUES (NULL)")
            conn.commit()
    assert bl.storage.list()[0].diagnosis.subtype == "not_null_violation"


def test_none_from_nullable_column_is_data_shape(bl, db):
    with pytest.raises(TypeError):
        with bl.capture(name="profile"):
            row = open_db(db).execute("SELECT age FROM users WHERE email='b@example.com'").fetchone()
            _ = row[0] + 1
    diag = bl.storage.list()[0].diagnosis
    assert diag.category == "data_shape"
    assert diag.subtype in {"unexpected_none", "type_mismatch"}


def test_missing_key_is_data_shape(bl):
    with pytest.raises(KeyError):
        with bl.capture(name="serialize"):
            {"id": 1}["name"]
    diag = bl.storage.list()[0].diagnosis
    assert diag.category == "data_shape"
    assert diag.subtype == "missing_key"


def test_parse_error_is_validation(bl):
    with pytest.raises(ValueError):
        with bl.capture(name="parse"):
            int("not-a-number")
    assert bl.storage.list()[0].diagnosis.category == "validation"


def test_analyzer_matches_foreign_drivers_without_import():
    class UndefinedTable(Exception):
        pass

    UndefinedTable.__module__ = "psycopg2.errors"
    engine = AnalyzerEngine()
    verdict = engine.analyze(
        AnalysisInput(
            exception=UndefinedTable('relation "orders" does not exist'),
            error_type="UndefinedTable",
            error_module="psycopg2.errors",
            error_message='relation "orders" does not exist',
        )
    )
    assert verdict.category == "database"
    assert verdict.subtype == "missing_table"


def test_pool_exhaustion_rule():
    engine = AnalyzerEngine()
    verdict = engine.analyze(
        AnalysisInput(
            error_type="TimeoutError",
            error_module="sqlalchemy.exc",
            error_message="QueuePool limit of size 5 overflow 10 reached, connection timed out",
        )
    )
    assert verdict.subtype == "pool_exhausted"


def test_custom_analyzer_wins(bl):
    class MyAnalyzer(BaseAnalyzer):
        name = "custom"
        priority = 1

        def analyze(self, data):
            if "tenant" in data.error_message:
                return self.verdict(category="tenancy", title="Tenant problem", summary="x")
            return None

    bl.analyzers.register(MyAnalyzer())
    with pytest.raises(RuntimeError):
        with bl.capture(name="job"):
            raise RuntimeError("tenant is missing")
    assert bl.storage.list()[0].category == "tenancy"


def test_n_plus_one_detection(db):
    bl = JSCoup("t", storage=MemoryStorage(), n_plus_one_threshold=5, capture_success=False)
    with bl.capture(name="list-orders"):
        conn = open_db(db)
        for _ in range(6):
            conn.execute("SELECT * FROM users WHERE id = ?", (1,)).fetchone()
    event = bl.storage.list()[0]
    assert event.status == "slow"
    assert event.diagnosis.subtype == "n_plus_one"


# --------------------------------------------------------------------------- #
# auth/access capture and detection
# --------------------------------------------------------------------------- #


def test_401_status_only_is_captured_by_default(bl):
    """Before capture_auth_failures existed, a 401/403 with no exception (e.g. a
    framework errorhandler that already turned it into a plain response) was
    silently dropped unless capture_4xx was also enabled. It must now always
    be captured and diagnosed as auth."""
    with bl.capture(name="check-token") as ctx:
        ctx.status_code = 401
    events = bl.storage.list()
    assert len(events) == 1
    assert events[0].status == "error"
    assert events[0].diagnosis.category == "auth"


def test_capture_auth_failures_can_be_disabled():
    bl = JSCoup("t", storage=MemoryStorage(), capture_success=False, capture_auth_failures=False)
    with bl.capture(name="check-token") as ctx:
        ctx.status_code = 401
    assert bl.storage.list() == []


def test_capture_4xx_still_governs_non_auth_status_codes(bl):
    with bl.capture(name="not-found") as ctx:
        ctx.status_code = 404
    assert bl.storage.list() == []  # unrelated to capture_auth_failures, unchanged behaviour


def test_exception_status_code_attribute_improves_auth_diagnosis(bl):
    """A custom exception with a .status_code (the demo app's AuthError pattern)
    should be attributed to auth even though its class name matches no built-in
    allowlist, as long as no framework already set ctx.status_code."""

    class AuthError(Exception):
        status_code = 401

    with pytest.raises(AuthError):
        with bl.capture(name="protected"):
            raise AuthError("missing token")
    assert bl.storage.list()[0].diagnosis.category == "auth"


def test_access_analyzer_is_registered_by_default():
    engine = AnalyzerEngine()
    assert any(a.name == "access" for a in engine.analyzers)


def test_403_status_is_access_not_auth():
    engine = AnalyzerEngine()
    verdict = engine.analyze(AnalysisInput(status_code=403))
    assert verdict.category == "access"
    assert verdict.subtype == "forbidden"


def test_401_status_is_still_auth_not_access():
    engine = AnalyzerEngine()
    verdict = engine.analyze(AnalysisInput(status_code=401))
    assert verdict.category == "auth"


def test_builtin_permission_error_is_access_not_generic(bl):
    """PermissionError previously matched no analyzer at all and fell through
    to the low-confidence generic catch-all."""
    with pytest.raises(PermissionError):
        with bl.capture(name="write-file"):
            raise PermissionError("Access is denied: 'C:\\protected\\file.txt'")
    diag = bl.storage.list()[0].diagnosis
    assert diag.category == "access"
    assert diag.subtype == "permission_denied"
    assert diag.analyzer == "access"


def test_string_concat_type_error_is_data_shape(bl):
    with pytest.raises(TypeError):
        with bl.capture(name="format-message"):
            "user id: " + 5
    diag = bl.storage.list()[0].diagnosis
    assert diag.category == "data_shape"
    assert diag.subtype == "str_concat_mismatch"
    assert diag.evidence["other_type"] == "int"


# --------------------------------------------------------------------------- #
# identity & redaction
# --------------------------------------------------------------------------- #


def test_static_token_resolution():
    bl = JSCoup("t", storage=MemoryStorage(),
                 static_tokens={"tok-1": {"subject": "42", "label": "alice@example.com"}})
    actor = bl.identity.resolve("tok-1")
    assert actor.subject == "42"
    assert actor.label == "alice@example.com"
    assert actor.token_fingerprint == fingerprint_token("tok-1")


def test_token_extraction_from_headers():
    bl = JSCoup("t", storage=MemoryStorage())
    token, source, scheme = bl.identity.extract(headers={"Authorization": "Bearer abc123"})
    assert (token, scheme) == ("abc123", "bearer")
    assert source == "header:Authorization"


def test_jwt_claims_are_decoded():
    import base64, json

    payload = base64.urlsafe_b64encode(json.dumps({"sub": "u-9", "email": "z@x.io"}).encode()).decode().rstrip("=")
    token = f"header.{payload}.signature"
    assert decode_jwt_payload(token)["sub"] == "u-9"
    bl = JSCoup("t", storage=MemoryStorage())
    actor = bl.identity.resolve(token)
    assert actor.subject == "u-9"
    assert actor.label == "z@x.io"


def test_raw_token_is_not_stored(bl):
    with pytest.raises(ValueError):
        with bl.capture(name="job", actor=bl.identity.resolve("super-secret-token")):
            raise ValueError("x")
    event = bl.storage.list()[0]
    assert "super-secret-token" not in str(event.to_dict())
    assert event.actor.token_fingerprint


def test_redactor_masks_sensitive_keys():
    r = Redactor(["password", "api_key"], mask="***")
    out = r.scrub({"user": "a", "password": "hunter2", "nested": {"api_key": "k"}})
    assert out == {"user": "a", "password": "***", "nested": {"api_key": "***"}}


def test_params_are_redacted(bl):
    with pytest.raises(RuntimeError):
        with bl.capture(name="login", params={"email": "a@b.c", "password": "hunter2"}):
            raise RuntimeError("x")
    assert bl.storage.list()[0].params["password"] == "[redacted]"


# --------------------------------------------------------------------------- #
# storage
# --------------------------------------------------------------------------- #


def test_sqlite_storage_roundtrip(tmp_path):
    storage = SQLiteStorage(db_path=str(tmp_path / "b.db"))
    bl = JSCoup("t", storage=storage)
    with pytest.raises(ValueError):
        with bl.capture(name="job", params={"a": 1}):
            raise ValueError("stored")
    events = storage.list()
    assert len(events) == 1
    loaded = storage.get(events[0].id)
    assert loaded.error_message == "stored"
    assert loaded.params == {"a": 1}
    assert storage.count(status="error") == 1
    assert storage.summary()["errors"] == 1
    assert storage.issues()[0]["count"] == 1


def test_storage_filters_and_search(tmp_path):
    storage = SQLiteStorage(db_path=str(tmp_path / "c.db"))
    bl = JSCoup("t", storage=storage)
    for name, exc in [("alpha", ValueError("first")), ("beta", KeyError("second"))]:
        with pytest.raises(type(exc)):
            with bl.capture(name=name):
                raise exc
    assert len(storage.list(search="alpha")) == 1
    assert len(storage.list(category="data_shape")) == 1
    assert storage.count(kind="service") == 2
    assert len(storage.list(since=time.time() + 10)) == 0


def test_storage_purge_and_resolve(tmp_path):
    storage = SQLiteStorage(db_path=str(tmp_path / "d.db"))
    bl = JSCoup("t", storage=storage)
    with pytest.raises(ValueError):
        with bl.capture(name="job"):
            raise ValueError("x")
    event_id = storage.list()[0].id
    assert storage.mark_resolved(event_id) is True
    assert storage.get(event_id).resolved is True
    assert storage.purge() == 1
    assert storage.list() == []


def test_sqlite_storage_orders_ties_deterministically(tmp_path, monkeypatch):
    """On a low-resolution clock (notably Windows), several fast events can share
    the exact same time.time() value. ``list()`` must still return the truly
    most-recent one first, using insertion order (rowid) as the tiebreaker."""
    storage = SQLiteStorage(db_path=str(tmp_path / "ties.db"))
    bl = JSCoup("t", storage=storage, capture_success=True)
    frozen = time.time()
    monkeypatch.setattr(time, "time", lambda: frozen)
    for i in range(5):
        with bl.capture(name=f"op-{i}"):
            pass
    assert storage.list(limit=1)[0].name == "op-4"


def test_grouping_by_fingerprint(bl):
    for i in range(3):
        with pytest.raises(ValueError):
            with bl.capture(name="job"):
                raise ValueError(f"user {i} not found")
    issues = bl.storage.issues()
    assert len(issues) == 1 and issues[0]["count"] == 3


# --------------------------------------------------------------------------- #
# lambda / service simulation
# --------------------------------------------------------------------------- #


def test_simulate_lambda_success(bl):
    def handler(event, context):
        return {"n": len(event["records"]), "fn": context.function_name}

    out = bl.simulate_lambda(handler, {"records": [1, 2]}, name="import")
    assert out["ok"] and out["result"]["n"] == 2
    assert bl.storage.list() == []  # success is not stored by default


def test_simulate_lambda_failure_is_analysed(bl):
    def handler(event, context):
        return event["missing"]

    out = bl.simulate_lambda(handler, {"records": []})
    assert out["ok"] is False
    event = bl.storage.get(out["event_id"])
    assert event.kind == "lambda"
    assert event.diagnosis.subtype == "missing_key"


def test_watch_lambda_captures_real_invocations(bl):
    """watch_lambda captures every real call, unlike simulate_lambda (above),
    which only runs a handler once, on demand, from the dashboard."""

    @bl.watch_lambda(name="import-handler")
    def handler(event, context):
        return event["missing"]

    with pytest.raises(KeyError):
        handler({"records": []}, None)

    events = bl.storage.list()
    assert len(events) == 1
    assert events[0].kind == "lambda"
    assert events[0].name == "import-handler"

    target = bl.registry.get("service:import-handler")
    assert target is not None
    assert target.framework == "lambda"


def test_watch_lambda_success_passes_through_unstored_by_default(bl):
    @bl.watch_lambda()
    def handler(event, context):
        return {"ok": True}

    result = handler({"x": 1}, None)

    assert result == {"ok": True}
    assert bl.storage.list() == []  # success is not stored by default


def test_registry_exposes_watched_services(bl):
    @bl.watch(kind="service", description="does things")
    def my_service(a: int, b: str = "x"):
        return a

    target = bl.registry.get(my_service.__jscoup_target__)
    assert target is not None
    names = [p.name for p in target.params]
    assert names == ["a", "b"]
    assert target.params[1].required is False


def test_invoke_refuses_a_python_function_and_never_runs_it(bl):
    """JSCoup is middleware: it replays HTTP APIs and records the outcome, but
    it does not execute application code itself."""
    ran = []

    @bl.watch(kind="service", name="risky")
    def risky(x: int):
        ran.append(x)
        return 10 // x

    result = bl.invoke("service:risky", params={"x": 5})

    assert result["ok"] is False
    assert "not an HTTP API" in result["error"]
    assert ran == []


# --------------------------------------------------------------------------- #
# dashboard API
# --------------------------------------------------------------------------- #


def test_dashboard_api_routes(bl):
    with pytest.raises(ValueError):
        with bl.capture(name="job"):
            raise ValueError("dash")
    api = bl.dashboard

    assert api.handle("/api/health").status == 200
    listing = api.handle("/api/events")
    assert b"dash" in listing.body
    event_id = bl.storage.list()[0].id
    detail = api.handle(f"/api/events/{event_id}")
    assert detail.status == 200 and b"diagnosis" in detail.body
    assert api.handle("/api/events/does-not-exist").status == 404
    assert api.handle("/api/summary").status == 200
    assert api.handle("/api/issues").status == 200
    assert api.handle("/api/timeline").status == 200
    page = api.handle("/")
    assert page.content_type.startswith("text/html") and b"JSCoup" in page.body
    assert api.handle("/api/purge", method="POST").status == 200
    assert bl.storage.list() == []


def test_dashboard_token_protection():
    bl = JSCoup("t", storage=MemoryStorage(), dashboard_token="s3cret")
    assert bl.dashboard.handle("/api/health").status == 401
    assert bl.dashboard.handle("/api/health", query={"token": "s3cret"}).status == 401
    assert bl.dashboard.handle("/api/health", headers={"X-JSCoup-Token": "s3cret"}).status == 200
    assert bl.dashboard.handle("/api/health", headers={"X-JSCoup-Token": "s3cret"}).status == 200


def test_live_invoke_can_be_disabled():
    bl = JSCoup("t", storage=MemoryStorage(), allow_live_invoke=False, dashboard_local_dev=True)
    res = bl.dashboard.handle("/api/invoke", method="POST", body=b'{"target_id":"x"}')
    assert res.status == 403


def test_config_from_dict_and_merge():
    config = JSCoupConfig.from_dict({"service_name": "x", "unknown": 1})
    assert config.service_name == "x"
    assert config.merged(environment="prod").environment == "prod"
