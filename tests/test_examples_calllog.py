# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Smart examples, the always-on call log with retention, and the Postman
export."""

from __future__ import annotations

import json
import time

import pytest

from jscoup import JSCoup, MemoryStorage
from jscoup.calllog import CallLogStore
from jscoup.examples import (
    build_expected_responses, default_error_example, request_body_example, sample_value,
)
from jscoup.postman import build_postman_collection
from jscoup.registry import ParamSpec, Registry, Target


# ---- examples ------------------------------------------------------------- #

def test_sample_value_uses_the_declared_default():
    assert sample_value("rows", "int", 10) == 10


@pytest.mark.parametrize("name,type_,expected", [
    ("email", "str", "user@example.com"),
    ("dataset_id", "int", 1),
    ("count", "int", 1),
    ("price", "float", 1.5),
    ("active", "bool", True),
    ("tags", "list[str]", ["a", "b"]),
    ("filter", "dict", {"key": "value"}),
    ("note", "str", "example-note"),
])
def test_sample_value_by_name_and_type(name, type_, expected):
    assert sample_value(name, type_) == expected


def test_request_body_example_covers_body_params_only():
    params = [
        ParamSpec(name="id", location="path", type="int"),
        ParamSpec(name="email", location="body", type="str"),
        ParamSpec(name="age", location="body", type="int"),
    ]
    assert request_body_example(params) == {"email": "user@example.com", "age": 1}


def test_request_body_example_is_none_without_body_params():
    assert request_body_example([ParamSpec(name="id", location="path")]) is None


def test_explicit_param_example_wins():
    params = [ParamSpec(name="email", location="body", type="str", example="boss@corp.io")]
    assert request_body_example(params) == {"email": "boss@corp.io"}


def test_default_error_examples_exist_for_common_statuses():
    for code in (400, 401, 403, 404, 422, 429, 500, 503):
        assert "error" in default_error_example(code)


def test_expected_responses_prefers_override_then_seen_then_default():
    result = build_expected_responses(
        "GET", [ParamSpec(name="id", location="path")], False,
        seen={200: {"id": 7}, 404: {"error": "real one"}},
        overrides={200: {"id": 99}},
    )
    assert result["200"]["example"] == {"id": 99}
    assert result["404"]["example"] == {"error": "real one"}
    assert result["400"]["example"]["error"] == "Bad Request"
    assert "500" in result


def test_expected_responses_adds_auth_statuses_when_protected():
    result = build_expected_responses("GET", [], True)
    assert "401" in result and "403" in result


# ---- describe() overrides -------------------------------------------------- #

def test_describe_overrides_examples_and_survives_rediscovery():
    registry = Registry()
    registry.describe(
        method="POST", path="/users", request_example={"email": "a@b.c"},
        response_examples={201: {"id": 1}}, params_example={"email": "override@x.io"},
    )
    target = Target(
        id="http:POST:/users", kind="http", name="create_user", method="POST", path="/users",
        params=[ParamSpec(name="email", location="body", type="str")],
    )
    registry.add(target)

    listed = registry.to_list()[0]
    assert listed["request_example"] == {"email": "a@b.c"}
    assert listed["params"][0]["example"] == "override@x.io"
    assert registry.get("http:POST:/users").response_examples == {201: {"id": 1}}


# ---- call log --------------------------------------------------------------- #

def _record(store, name="GET /x", status=200, ok=True, preview=None, **kw):
    store.record(kind="http", name=name, method="GET", path="/x", status_code=status, ok=ok,
                 duration_ms=5.0, actor=None, response_preview=preview, **kw)


def test_call_log_records_and_lists_newest_first(tmp_path):
    store = CallLogStore(str(tmp_path / "c.db"))
    _record(store, name="GET /a")
    time.sleep(0.01)
    _record(store, name="GET /b")

    assert [c["name"] for c in store.recent()] == ["GET /b", "GET /a"]


def test_call_log_summary_counts_success_and_failure_per_api(tmp_path):
    store = CallLogStore(str(tmp_path / "c.db"))
    _record(store, name="GET /a")
    _record(store, name="GET /a")
    _record(store, name="GET /a", status=500, ok=False)

    summary = store.summary()

    assert summary["total_calls"] == 3
    assert summary["succeeded"] == 2 and summary["failed"] == 1
    api = summary["apis"][0]
    assert (api["calls"], api["succeeded"], api["failed"]) == (3, 2, 1)


def test_call_log_filters_by_ok(tmp_path):
    store = CallLogStore(str(tmp_path / "c.db"))
    _record(store)
    _record(store, status=500, ok=False)

    assert len(store.recent(ok=False)) == 1
    assert len(store.recent(ok=True)) == 1


def test_call_log_purges_rows_older_than_the_cutoff(tmp_path):
    store = CallLogStore(str(tmp_path / "c.db"))
    _record(store)
    store.conn.execute("UPDATE call_log SET ts = ?", (time.time() - 40 * 86400,))
    store.conn.commit()
    _record(store)

    deleted = store.purge_older_than(time.time() - 30 * 86400)

    assert deleted == 1
    assert store.count() == 1


def test_call_log_omits_response_bodies(tmp_path):
    store = CallLogStore(str(tmp_path / "c.db"))
    _record(store, status=200, preview='{"n": 1}')
    time.sleep(0.01)
    _record(store, status=200, preview='{"n": 2}')
    _record(store, status=404, ok=False, preview='{"error": "nope"}')

    seen = store.seen_statuses("GET /x")

    assert seen == {}


def test_every_call_is_logged_even_with_capture_success_off():
    bl = JSCoup("t", storage=MemoryStorage(), capture_success=False, dashboard_local_dev=True)

    @bl.watch(kind="service", name="ping")
    def ping():
        return {"pong": True}

    ping()

    assert bl.storage.list() == []  # nothing in the full event pipeline
    logged = bl.call_log.recent()
    assert len(logged) == 1 and logged[0]["name"] == "ping" and logged[0]["ok"] == 1


def test_failed_calls_are_logged_as_failures():
    bl = JSCoup("t", storage=MemoryStorage(), dashboard_local_dev=True)

    @bl.watch(kind="service", name="boom")
    def boom():
        raise ValueError("no")

    with pytest.raises(ValueError):
        boom()

    assert bl.call_log.recent()[0]["ok"] == 0


def test_call_log_can_be_switched_off():
    bl = JSCoup("t", storage=MemoryStorage(), call_log_enabled=False, dashboard_local_dev=True)

    @bl.watch(kind="service", name="ping")
    def ping():
        return 1

    ping()

    assert bl.call_log.recent() == []


def test_old_rows_are_purged_automatically_using_the_configured_retention():
    bl = JSCoup("t", storage=MemoryStorage(), call_log_retention_days=30, dashboard_local_dev=True)

    @bl.watch(kind="service", name="ping")
    def ping():
        return 1

    ping()
    bl.call_log.conn.execute("UPDATE call_log SET ts = ?", (time.time() - 45 * 86400,))
    bl.call_log.conn.commit()
    bl._last_call_log_purge = -10_000.0  # as if an hour has passed
    ping()

    assert bl.call_log.count() == 1  # the 45-day-old row is gone, the new one stays


# ---- routes / postman -------------------------------------------------------- #

@pytest.fixture
def admin(tmp_path):
    bl = JSCoup("t", storage=MemoryStorage(), dashboard_username="admin", dashboard_password="s3cret-pass",
                dashboard_session_db_path=str(tmp_path / "s.db"))
    response = bl.dashboard.handle(
        "/api/login", method="POST", body=json.dumps({"username": "admin", "password": "s3cret-pass"}).encode(),
    )
    cookie = {"Cookie": response.headers["Set-Cookie"].split(";", 1)[0]}
    return bl, cookie


def test_call_log_routes_report_every_call(admin):
    bl, cookie = admin

    @bl.watch(kind="service", name="ping")
    def ping():
        return {"pong": True}

    ping()
    ping()

    summary = json.loads(bl.dashboard.handle("/api/call-log/summary", headers=cookie).body)
    listing = json.loads(bl.dashboard.handle("/api/call-log", headers=cookie).body)

    assert summary["total_calls"] == 2 and summary["apis"][0]["name"] == "ping"
    assert len(listing["calls"]) == 2 and listing["retention_days"] == 30


def test_targets_carry_expected_responses_and_param_examples(admin):
    bl, cookie = admin
    bl.registry.add(Target(
        id="http:POST:/add", kind="http", name="add", method="POST", path="/add",
        params=[ParamSpec(name="a", location="body", type="int", required=True),
                ParamSpec(name="b", location="body", type="float", required=False, default=2.5)],
    ))

    targets = json.loads(bl.dashboard.handle("/api/targets", headers=cookie).body)["targets"]
    target = next(t for t in targets if t["id"] == "http:POST:/add")

    assert {p["name"]: p["example"] for p in target["params"]} == {"a": 1, "b": 2.5}
    assert "200" in target["expected_responses"] and "500" in target["expected_responses"]


def test_expected_response_never_uses_a_real_seen_body(admin):
    bl, cookie = admin
    bl.registry.add(Target(id="http:GET:/ping", kind="http", name="ping", method="GET", path="/ping"))
    bl.call_log.record(kind="http", name="GET /ping", method="GET", path="/ping", status_code=200, ok=True,
                       duration_ms=1.0, actor=None, response_preview='{"real": "body"}')

    targets = json.loads(bl.dashboard.handle("/api/targets", headers=cookie).body)["targets"]
    target = next(t for t in targets if t["id"] == "http:GET:/ping")

    assert target["expected_responses"]["200"]["example"] == {"ok": True}


def test_target_lists_only_contain_http_apis(admin):
    bl, cookie = admin
    bl.registry.add(Target(id="http:GET:/ping", kind="http", name="ping", method="GET", path="/ping"))
    bl.registry.register_callable(lambda: None, name="job")

    targets = json.loads(bl.dashboard.handle("/api/targets", headers=cookie).body)["targets"]

    assert [t["id"] for t in targets] == ["http:GET:/ping"]


def test_postman_export_is_a_valid_collection(admin):
    bl, cookie = admin
    bl.registry.add(Target(
        id="http:POST:/api/users", kind="http", name="create_user", method="POST", path="/api/users",
        requires_auth=True, tags=["users"],
        params=[ParamSpec(name="email", location="body", type="str", required=True)],
    ))
    bl.registry.add(Target(
        id="http:GET:/api/users/{user_id}", kind="http", name="get_user", method="GET",
        path="/api/users/{user_id}", tags=["users"],
        params=[ParamSpec(name="user_id", location="path", type="int", required=True)],
    ))

    response = bl.dashboard.handle("/api/postman.json", headers=cookie)
    collection = json.loads(response.body)

    assert "attachment" in response.headers["Content-Disposition"]
    assert collection["info"]["schema"].endswith("collection.json")
    folder = collection["item"][0]
    assert folder["name"] == "users"
    by_name = {i["name"]: i for i in folder["item"]}
    post = by_name["POST /api/users"]["request"]
    assert json.loads(post["body"]["raw"]) == {"email": "user@example.com"}
    assert {"key": "Authorization", "value": "Bearer {{token}}"} in post["header"]
    get = by_name["GET /api/users/{user_id}"]["request"]
    assert get["url"]["path"] == ["api", "users", ":user_id"]
    assert get["url"]["variable"][0]["value"] == "1"
    assert by_name["GET /api/users/{user_id}"]["response"]


def test_postman_builder_skips_services():
    collection = build_postman_collection("svc", [{"kind": "service", "name": "x"}], "http://h")
    assert collection["item"] == []


# ---- real response bodies, FastAPI Body() defaults ------------------------------- #

def _fastapi_app(bl):
    fastapi = pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    app = fastapi.FastAPI()

    @app.get("/thing")
    def thing():
        return {"id": 7, "name": "widget"}

    @app.post("/filter")
    def do_filter(spec: dict = fastapi.Body(...)):
        return spec

    bl.install(app)
    return TestClient(app)


def test_fastapi_call_log_retains_metadata_only():
    bl = JSCoup("t", storage=MemoryStorage(), dashboard_local_dev=True, dashboard_mount_in_app=False)
    client = _fastapi_app(bl)

    assert client.get("/thing").status_code == 200

    logged = [c for c in bl.call_log.recent() if c["name"] == "GET /thing"][0]
    assert logged["response_preview"] is None
    assert logged["ok"] == 1 and logged["status_code"] == 200


def test_fastapi_body_marker_is_not_mistaken_for_a_default():
    bl = JSCoup("t", storage=MemoryStorage(), dashboard_local_dev=True, dashboard_mount_in_app=False)
    _fastapi_app(bl)

    target = bl.registry.get("http:POST:/filter")

    assert target.params[0].required is True and target.params[0].default is None
    assert target.to_dict()["request_example"] == {"key": "value"}


# --------------------------------------------------------------------------- #
# file upload (multipart) + response content type
# --------------------------------------------------------------------------- #


def _serve_once(handler_body, content_type):
    import http.server
    import threading

    seen = {}

    class H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            seen["ctype"] = self.headers.get("Content-Type", "")
            seen["body"] = self.rfile.read(n)
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.end_headers()
            self.wfile.write(handler_body)

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, seen


def test_file_param_is_sent_as_multipart_and_html_reply_keeps_raw_text():
    import base64

    from jscoup import JSCoup
    from jscoup.storage.memory import MemoryStorage

    srv, seen = _serve_once(b"<!doctype html>\n<html><body>hi</body></html>", "text/html; charset=utf-8")
    try:
        bl = JSCoup("t", storage=MemoryStorage(), base_url=f"http://127.0.0.1:{srv.server_port}", dashboard_local_dev=True)
        bl.registry.add_manual("POST", "/upload", "upload")
        target = next(t for t in bl.registry.all() if t.path == "/upload")
        payload = {"filename": "a.png", "content_type": "image/png", "data": base64.b64encode(b"PNGDATA").decode()}
        res = bl.simulator.invoke(target.id, params={"photo": payload, "caption": "hello"})
    finally:
        srv.shutdown()
    assert seen["ctype"].startswith("multipart/form-data; boundary=")
    assert b'name="photo"; filename="a.png"' in seen["body"]
    assert b"PNGDATA" in seen["body"]
    assert b'name="caption"' in seen["body"] and b"hello" in seen["body"]
    assert res["content_type"] == "text/html"
    assert res["response"].startswith("<!doctype html>\n<html>")


def test_oversized_upload_is_refused_without_sending():
    import base64

    from jscoup import simulator as sim

    big = {"filename": "x.bin", "content_type": "application/octet-stream",
           "data": base64.b64encode(b"0" * (sim.MAX_UPLOAD_BYTES + 1)).decode()}
    try:
        sim._encode_multipart({}, {"f": big})
    except ValueError as exc:
        assert "larger than" in str(exc)
    else:
        raise AssertionError("expected ValueError")


# --------------------------------------------------------------------------- #
# Django views: methods + parameters read from the view's own source
# --------------------------------------------------------------------------- #


def _read_body(request):
    return {}


def _django_sample_view():
    from django.views.decorators.http import require_http_methods

    @require_http_methods(["GET", "POST"])
    def guests(request):
        if request.method == "POST":
            data = _read_body(request)
            return (data["name"], data.get("email", ""), int(data.get("age", 0)))
        page = request.GET.get("page", 1)
        term = request.GET["q"]
        photo = request.FILES.get("photo")
        return page, term, photo

    return guests


def test_django_view_methods_and_params_are_read_from_source():
    from jscoup.registry import _django_view_info

    methods, query, body = _django_view_info(_django_sample_view())
    assert methods == ["GET", "POST"]
    q = {p.name: p for p in query}
    assert q["q"].required and not q["page"].required and q["page"].type == "int"
    b = {p.name: p for p in body}
    assert b["name"].required and not b["email"].required
    assert b["age"].type == "int"
    assert b["photo"].type == "file"


def test_id_examples_follow_the_parameters_type():
    from jscoup.examples import EXAMPLE_UUID, sample_value

    assert sample_value("id_sped", "str") == EXAMPLE_UUID      # a string id is most likely a UUID
    assert sample_value("order_id", "uuid") == EXAMPLE_UUID
    assert sample_value("booking_id", "int") == 1              # an integer id is a number
    assert sample_value("user_id") == 1                        # unknown type keeps the old guess
    assert sample_value("paid", "bool") is True                # "...id" in the name must not beat the type


def test_a_validators_date_pattern_gives_a_valid_date_example():
    import re

    from flask import Flask

    from jscoup.registry import Registry

    marker = type("Json", (), {"name": "json", "__module__": "flask_parameter_validation.parameter_types.json",
                               "default": None, "pattern": r"\d{4}-\d{2}-\d{2}"})()
    app = Flask(__name__)

    @app.route("/orders", methods=["POST"])
    def create(issued: str = marker):
        return "x"

    registry = Registry()
    registry.discover_flask(app)

    example = registry.get("http:POST:/orders").to_dict()["params"][0]["example"]
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", example)
