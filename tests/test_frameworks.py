# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""End-to-end tests against Flask, FastAPI and Django."""

import json
import sqlite3
import sys

import pytest

from jscoup import JSCoup, MemoryStorage, connect

TOKENS = {
    "demo-token-alice": {"subject": "1", "label": "alice@example.com", "role": "admin"},
}


@pytest.fixture
def db(tmp_path):
    path = str(tmp_path / "app.db")
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, age INTEGER);
        INSERT INTO users (email, age) VALUES ('a@example.com', 30);
        """
    )
    conn.commit()
    conn.close()
    return path


# --------------------------------------------------------------------------- #
# Flask
# --------------------------------------------------------------------------- #


@pytest.fixture
def flask_client(db):
    from flask import Flask, jsonify, request

    bl = JSCoup("flask-test", storage=MemoryStorage(), static_tokens=TOKENS, dashboard_local_dev=True)
    app = Flask(__name__)  # TESTING stays off so errors become 500s, as in production

    @app.get("/ping")
    def ping():
        return jsonify(ok=True)

    @app.post("/users")
    def create_user():
        """Requires token."""
        payload = request.get_json(silent=True) or {}
        conn = connect(db)
        conn.execute("INSERT INTO users (email, age) VALUES (?, ?)",
                     (payload.get("email"), payload.get("age")))
        conn.commit()
        return jsonify(created=True), 201

    @app.get("/crash")
    def crash():
        return jsonify(v=1 / 0)

    bl.install(app)
    return bl, app.test_client()


def test_flask_captures_unhandled_error(flask_client):
    bl, client = flask_client
    assert client.get("/ping").status_code == 200
    assert client.get("/crash").status_code == 500
    events = bl.storage.list()
    assert len(events) == 1
    event = events[0]
    assert event.kind == "http"
    assert event.route == "/crash"
    assert event.status_code == 500
    assert event.error_type == "ZeroDivisionError"
    assert event.diagnosis is not None


def test_flask_captures_db_error_with_actor_and_sql(flask_client):
    bl, client = flask_client
    response = client.post(
        "/users",
        json={"email": "a@example.com", "age": 20, "password": "hunter2"},
        headers={"Authorization": "Bearer demo-token-alice"},
    )
    assert response.status_code == 500
    event = bl.storage.list()[0]
    assert event.category == "database"
    assert event.diagnosis.subtype == "unique_violation"
    assert event.actor.label == "alice@example.com"
    assert event.actor.token_fingerprint
    assert event.params["password"] == "[redacted]"
    assert any("INSERT INTO users" in q.sql for q in event.queries)
    assert event.headers.get("Authorization") == "[redacted]"


def test_flask_dashboard_and_targets(flask_client):
    bl, client = flask_client
    client.get("/crash")
    assert b"JSCoup" in client.get("/__jscoup/").data
    events = client.get("/__jscoup/api/events").get_json()
    assert events["total"] == 1
    detail = client.get(f"/__jscoup/api/events/{events['events'][0]['id']}").get_json()
    assert detail["diagnosis"]["title"]
    targets = {t["id"] for t in client.get("/__jscoup/api/targets").get_json()["targets"]}
    assert "http:GET:/crash" in targets and "http:POST:/users" in targets
    assert client.get("/__jscoup/api/summary").get_json()["errors"] == 1
    # the dashboard itself must never be captured
    assert bl.storage.count() == 1


def test_flask_handled_error_response_is_not_an_event(flask_client):
    bl, client = flask_client
    assert client.get("/does-not-exist").status_code == 404
    assert bl.storage.count() == 0  # 4xx is off by default


def test_flask_errorhandler_401_is_now_captured():
    """Regression test for a verified gap: a Flask ``@app.errorhandler`` that
    catches a custom auth exception and returns a plain response (never
    re-raising) used to be completely invisible to JSCoup, because Flask's
    ``got_request_exception`` signal only fires when *no* errorhandler catches
    the exception. ``capture_auth_failures`` (on by default) closes this by
    capturing any 401/403 outcome regardless of whether an exception ever
    reached JSCoup's own exception hook."""
    from flask import Flask, jsonify, request

    class AuthError(Exception):
        status_code = 401

    bl = JSCoup("flask-auth-test", storage=MemoryStorage())
    app = Flask(__name__)

    @app.errorhandler(AuthError)
    def _handle_auth_error(exc):
        return jsonify(error=str(exc)), 401

    @app.get("/secret")
    def secret():
        if not request.headers.get("Authorization"):
            raise AuthError("Missing Authorization header")
        return jsonify(ok=True)

    bl.install(app)
    client = app.test_client()

    assert client.get("/secret").status_code == 401
    events = bl.storage.list()
    assert len(events) == 1
    assert events[0].status_code == 401
    assert events[0].diagnosis.category in ("auth", "access")


# --------------------------------------------------------------------------- #
# FastAPI
# --------------------------------------------------------------------------- #


@pytest.fixture
def fastapi_client(db):
    from fastapi import FastAPI, Header
    from fastapi.testclient import TestClient

    bl = JSCoup("fastapi-test", storage=MemoryStorage(), static_tokens=TOKENS, dashboard_local_dev=True)
    app = FastAPI()

    @app.get("/ping")
    def ping():
        return {"ok": True}

    @app.get("/users/{user_id}/profile")
    def profile(user_id: int):
        row = connect(db).execute("SELECT age FROM users WHERE id = ?", (user_id,)).fetchone()
        return {"next_year": row[0] + 1}

    @app.post("/users")
    async def create_user(payload: dict):
        conn = connect(db)
        conn.execute("INSERT INTO users (email, age) VALUES (?, ?)",
                     (payload.get("email"), payload.get("age")))
        conn.commit()
        return {"created": True}

    bl.install(app)
    return bl, TestClient(app, raise_server_exceptions=False)


def test_fastapi_captures_path_params_and_db(fastapi_client):
    bl, client = fastapi_client
    assert client.get("/ping").status_code == 200
    assert client.get("/users/999/profile").status_code == 500
    event = bl.storage.list()[0]
    assert event.route == "/users/{user_id}/profile"
    assert event.params.get("user_id") in (999, "999")
    assert event.category == "data_shape"
    assert event.query_count == 1


def test_fastapi_captures_json_body_and_token(fastapi_client):
    bl, client = fastapi_client
    response = client.post(
        "/users",
        json={"email": "a@example.com", "age": 22, "api_key": "secret"},
        headers={"Authorization": "Bearer demo-token-alice"},
    )
    assert response.status_code == 500
    event = bl.storage.list()[0]
    assert event.diagnosis.subtype == "unique_violation"
    assert event.actor.subject == "1"
    assert event.params["api_key"] == "[redacted]"


def test_fastapi_dashboard(fastapi_client):
    bl, client = fastapi_client
    client.get("/users/999/profile")
    assert client.get("/__jscoup/").status_code == 200
    payload = client.get("/__jscoup/api/events").json()
    assert payload["total"] == 1
    health = client.get("/__jscoup/api/health").json()
    assert health["ok"] and health["targets"] >= 3


def test_fastapi_discovers_routes_behind_nested_included_routers():
    """Regression test: a real project typically organizes many routers as
    ``app.include_router(api_router)`` where ``api_router`` itself is built
    from ``api_router.include_router(sub_router)`` calls (one sub-router per
    feature area) rather than routes added directly via ``@app.get(...)``.
    On newer Starlette versions this nesting is represented internally by an
    opaque router-inclusion wrapper, not a flat list — discovery must unwrap
    it (see ``registry._iter_fastapi_routes``), not just skip it."""
    from fastapi import APIRouter, FastAPI

    bl = JSCoup("nested-router-test", storage=MemoryStorage())
    app = FastAPI()

    leaf_router = APIRouter()

    @leaf_router.get("/widgets")
    def list_widgets():
        return {"widgets": []}

    parent_router = APIRouter()
    parent_router.include_router(leaf_router, prefix="/v1")
    app.include_router(parent_router)

    bl.install(app)
    ids = {t.id for t in bl.registry.all()}
    assert "http:GET:/v1/widgets" in ids


def test_fastapi_route_added_after_install_is_still_discovered():
    """Regression test: install(app) snapshots routes once, at call time. A
    route defined below it (a common real-world ordering slip — e.g. a root
    "/" landing route added after install_jscoup(app) in main.py) used to
    stay permanently invisible. The dashboard now calls refresh_targets()
    before every request it serves, so this self-heals with no code change
    required in the monitored app."""
    from fastapi import FastAPI

    bl = JSCoup("late-route-test", storage=MemoryStorage())
    app = FastAPI()
    bl.install(app)

    @app.get("/added-after-install")
    def added_after_install():
        return {"ok": True}

    assert "http:GET:/added-after-install" not in {t.id for t in bl.registry.all()}
    bl.refresh_targets()
    assert "http:GET:/added-after-install" in {t.id for t in bl.registry.all()}


def test_fastapi_expands_pydantic_body_into_typed_params_with_descriptions():
    from fastapi import FastAPI
    from pydantic import BaseModel, Field

    from typing import Optional

    class CreateUser(BaseModel):
        email: str = Field(..., description="the user's login email")
        age: int = 0
        nickname: Optional[str] = None

    bl = JSCoup("pydantic-params-test", storage=MemoryStorage())
    app = FastAPI()

    @app.post("/users", tags=["users"])
    def create_user(payload: CreateUser):
        return {"created": True}

    bl.install(app)
    target = bl.registry.get("http:POST:/users")
    by_name = {p.name: p for p in target.params}
    assert by_name["email"].required is True
    assert by_name["email"].description == "the user's login email"
    assert by_name["age"].type == "int"
    assert by_name["age"].required is False
    assert by_name["nickname"].required is False
    assert target.tags == ["users"]


def test_fastapi_dependency_params_are_not_listed_as_inputs():
    """FastAPI DI params (a DB session, an auth-guard dependency) are supplied
    by the framework, never by the caller — they must not show up in the Live
    Tester as fields to fill in."""
    from fastapi import Depends, FastAPI

    def get_db():
        return "session"

    def current_user(db=Depends(get_db)):
        return "user"

    bl = JSCoup("di-params-test", storage=MemoryStorage())
    app = FastAPI()

    @app.get("/me")
    def me(db=Depends(get_db), user=Depends(current_user)):
        return {"user": user}

    bl.install(app)
    target = bl.registry.get("http:GET:/me")
    assert target.params == []


def test_describe_overrides_survive_rediscovery():
    """bl.describe() lets a developer hand-write documentation for an endpoint
    and its parameters; it must keep applying every time refresh_targets()
    re-runs discovery (which now happens on every dashboard request)."""
    from fastapi import FastAPI

    bl = JSCoup("describe-test", storage=MemoryStorage())
    app = FastAPI()

    @app.get("/widgets")
    def list_widgets(limit: int = 10):
        return {"widgets": []}

    bl.install(app)
    bl.describe(
        "/widgets", method="GET",
        description="List all widgets.",
        params={"limit": "max number of widgets to return"},
    )
    bl.refresh_targets()  # simulate the dashboard re-scanning routes
    target = bl.registry.get("http:GET:/widgets")
    assert target.description == "List all widgets."
    assert next(p for p in target.params if p.name == "limit").description == \
        "max number of widgets to return"


def test_fastapi_dependency_401_is_now_captured():
    """Regression test for the same gap on FastAPI/Starlette: an ``HTTPException``
    raised from a dependency is resolved by Starlette's own exception handling
    before it reaches JSCoup's ASGI middleware, so no exception object is ever
    seen there either — only ``capture_auth_failures`` makes this visible."""
    from fastapi import Depends, FastAPI, Header, HTTPException
    from fastapi.testclient import TestClient

    def require_token(authorization: str = Header(default=None)):
        if not authorization:
            raise HTTPException(status_code=401, detail="Missing Authorization header")
        return authorization

    bl = JSCoup("fastapi-auth-test", storage=MemoryStorage())
    app = FastAPI()

    @app.get("/secret")
    def secret(token: str = Depends(require_token)):
        return {"ok": True}

    bl.install(app)
    client = TestClient(app, raise_server_exceptions=False)

    assert client.get("/secret").status_code == 401
    events = bl.storage.list()
    assert len(events) == 1
    assert events[0].status_code == 401
    assert events[0].diagnosis.category in ("auth", "access")


# --------------------------------------------------------------------------- #
# Django
# --------------------------------------------------------------------------- #


@pytest.fixture
def django_client(db):
    import django
    from django.conf import settings
    from django.http import JsonResponse
    from django.urls import path

    from jscoup.integrations.django import jscoup_urls, install_django

    bl = JSCoup("django-test", storage=MemoryStorage(), static_tokens=TOKENS, dashboard_local_dev=True)
    install_django(bl)

    def ping(request):
        return JsonResponse({"ok": True})

    def profile(request, user_id):
        row = connect(db).execute("SELECT age FROM users WHERE id = ?", (user_id,)).fetchone()
        return JsonResponse({"next_year": row[0] + 1})

    module = type(sys)("django_urlconf_test")
    module.urlpatterns = [
        path("ping", ping, name="ping"),
        path("users/<int:user_id>/profile", profile, name="profile"),
    ] + jscoup_urls(bl)
    sys.modules["django_urlconf_test"] = module

    if not settings.configured:
        settings.configure(
            DEBUG=False,
            SECRET_KEY="test",
            ALLOWED_HOSTS=["*"],
            ROOT_URLCONF="django_urlconf_test",
            MIDDLEWARE=["jscoup.integrations.django.JSCoupMiddleware"],
            DATABASES={},
            INSTALLED_APPS=[],
        )
        django.setup()
    else:  # pragma: no cover - only when another test configured Django first
        settings.ROOT_URLCONF = "django_urlconf_test"

    from django.test import Client

    return bl, Client(raise_request_exception=False)


def test_django_captures_and_serves_dashboard(django_client):
    bl, client = django_client
    assert client.get("/ping").status_code == 200
    assert client.get("/users/999/profile").status_code == 500
    event = bl.storage.list()[0]
    assert event.kind == "http"
    assert event.route == "users/<int:user_id>/profile"
    assert event.category == "data_shape"
    assert client.get("/__jscoup/").status_code == 200
    assert client.get("/__jscoup/api/events").json()["total"] == 1
    targets = {t["path"] for t in client.get("/__jscoup/api/targets").json()["targets"]}
    assert "/users/<int:user_id>/profile" in targets
    assert not any("__jscoup" in p for p in targets)
