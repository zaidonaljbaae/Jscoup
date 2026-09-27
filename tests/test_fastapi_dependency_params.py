# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Inputs declared by ``Depends(...)`` sub-dependencies must be discovered.

A route like ``def login(form: OAuth2PasswordRequestForm = Depends())`` needs
the caller to send ``username`` and ``password``; the dependency parameter
itself is injected by FastAPI, but its fields are real request inputs.
"""

from typing import Optional

import pytest

fastapi = pytest.importorskip("fastapi")
pytest.importorskip("multipart")

from fastapi import Depends, FastAPI, Query  # noqa: E402
from fastapi.security import OAuth2PasswordRequestForm  # noqa: E402

from jscoup.registry import Registry  # noqa: E402


def _params(app, method, path):
    registry = Registry()
    registry.discover_fastapi(app)
    target = registry.get(f"http:{method}:{path}")
    assert target is not None
    return {p.name: p for p in target.params}


def test_oauth2_password_form_fields_are_discovered():
    app = FastAPI()

    @app.post("/login")
    def login(form: OAuth2PasswordRequestForm = Depends()):
        return {}

    params = _params(app, "POST", "/login")

    assert params["username"].location == "form"
    assert params["username"].required is True
    assert params["password"].location == "form"
    assert params["password"].required is True
    assert params["scope"].required is False
    assert "form" not in params  # the injected dependency itself is not a parameter


def test_query_params_declared_by_a_dependency_are_discovered():
    app = FastAPI()

    def pagination(skip: int = 0, limit: int = Query(default=20)):
        return {"skip": skip, "limit": limit}

    @app.get("/items")
    def items(page: dict = Depends(pagination)):
        return page

    params = _params(app, "GET", "/items")

    assert params["skip"].location == "query"
    assert params["skip"].type == "int"
    assert params["skip"].required is False
    assert params["limit"].location == "query"


def test_dependency_without_request_inputs_adds_nothing():
    app = FastAPI()

    def get_db():
        return object()

    @app.get("/ping")
    def ping(db=Depends(get_db)):
        return {}

    assert _params(app, "GET", "/ping") == {}


def test_a_route_parameter_is_not_duplicated_by_its_dependency():
    app = FastAPI()

    def pagination(limit: int = 10):
        return limit

    @app.get("/items")
    def items(limit: int = 5, page: int = Depends(pagination)):
        return {}

    registry = Registry()
    registry.discover_fastapi(app)
    target = registry.get("http:GET:/items")

    assert [p.name for p in target.params].count("limit") == 1


# --- parameters: required/optional, rules, examples -------------------------------


def _target(app, method, path):
    registry = Registry()
    registry.discover_fastapi(app)
    return registry.get(f"http:{method}:{path}")


def test_oauth2_form_examples_respect_the_fields_own_rules():
    app = FastAPI()

    @app.post("/login")
    def login(form: OAuth2PasswordRequestForm = Depends()):
        return {}

    by_name = {p["name"]: p for p in _target(app, "POST", "/login").to_dict()["params"]}

    # grant_type only accepts "password"; a made-up example would be rejected.
    assert by_name["grant_type"]["example"] == "password"
    assert by_name["grant_type"]["constraints"]["pattern"] == "^password$"
    # Optional inputs are left empty instead of pre-filled with fake values.
    assert by_name["scope"]["example"] == ""
    assert by_name["client_id"]["example"] == ""
    assert by_name["client_secret"]["example"] == ""
    # Required inputs still get a usable example.
    assert by_name["username"]["example"] not in ("", None)
    assert by_name["password"]["example"] not in ("", None)


def test_own_form_parameters_are_form_not_query():
    from fastapi import Form

    app = FastAPI()

    @app.post("/signup")
    def signup(name: str = Form(...), nickname: str = Form(default="")):
        return {}

    params = {p.name: p for p in _target(app, "POST", "/signup").params}

    assert params["name"].location == "form" and params["name"].required is True
    assert params["nickname"].location == "form" and params["nickname"].required is False


def test_literal_enum_and_numeric_rules_become_choices_and_examples():
    import enum
    from typing import Literal

    from typing_extensions import Annotated

    class Color(str, enum.Enum):
        red = "red"
        blue = "blue"

    app = FastAPI()

    @app.get("/search")
    def search(
        mode: Literal["fast", "deep"],
        color: Color = Color.blue,
        page: Annotated[int, Query(ge=3)] = 3,
        note: str = "",
    ):
        return {}

    by_name = {p["name"]: p for p in _target(app, "GET", "/search").to_dict()["params"]}

    assert by_name["mode"]["choices"] == ["fast", "deep"] and by_name["mode"]["example"] == "fast"
    assert by_name["mode"]["required"] is True
    assert by_name["color"]["choices"] == ["red", "blue"]
    assert by_name["page"]["constraints"]["ge"] == 3
    assert by_name["page"]["required"] is False


def test_optional_query_parameter_is_optional_and_not_prefilled():
    app = FastAPI()

    @app.get("/items")
    def items(q: Optional[str] = None, limit: int = 10):
        return {}

    by_name = {p["name"]: p for p in _target(app, "GET", "/items").to_dict()["params"]}

    assert by_name["q"]["required"] is False and by_name["q"]["example"] == ""
    assert by_name["limit"]["required"] is False and by_name["limit"]["example"] == 10


# --- token detection --------------------------------------------------------------


def _auth(app, method, path):
    t = _target(app, method, path)
    return t.requires_auth, t.auth_optional, t.auth_scheme


def test_route_without_any_security_scheme_needs_no_token():
    app = FastAPI()

    @app.post("/login")
    def login(form: OAuth2PasswordRequestForm = Depends()):  # class named "OAuth2..." is not a guard
        return {}

    @app.get("/ping")
    def ping():
        return {}

    assert _auth(app, "POST", "/login") == (False, False, "")
    assert _auth(app, "GET", "/ping") == (False, False, "")


def test_token_is_detected_through_a_chain_of_dependencies():
    from fastapi.security import OAuth2PasswordBearer

    app = FastAPI()
    oauth2 = OAuth2PasswordBearer(tokenUrl="/login")

    def get_current_user(token: str = Depends(oauth2)):
        return token

    def get_current_admin(user=Depends(get_current_user)):
        return user

    @app.get("/me")
    def me(user=Depends(get_current_user)):
        return {}

    @app.delete("/things/{thing_id}")
    def remove(thing_id: int, admin=Depends(get_current_admin)):
        return {}

    assert _auth(app, "GET", "/me") == (True, False, "bearer")
    assert _auth(app, "DELETE", "/things/{thing_id}") == (True, False, "bearer")
    # The token itself is not a request parameter the caller fills in.
    assert "token" not in {p.name for p in _target(app, "GET", "/me").params}


def test_optional_token_scheme_is_reported_as_optional_not_required():
    from fastapi.security import OAuth2PasswordBearer

    app = FastAPI()
    optional = OAuth2PasswordBearer(tokenUrl="/login", auto_error=False)

    def maybe_user(token: Optional[str] = Depends(optional)):
        return token

    @app.get("/files")
    def files(user=Depends(maybe_user)):
        return {}

    assert _auth(app, "GET", "/files") == (False, True, "bearer")


def test_http_bearer_basic_and_api_key_schemes_are_named():
    from fastapi.security import APIKeyHeader, HTTPBasic, HTTPBearer

    app = FastAPI()
    bearer, basic, key = HTTPBearer(), HTTPBasic(), APIKeyHeader(name="X-API-Key")

    @app.get("/a")
    def a(c=Depends(bearer)):
        return {}

    @app.get("/b")
    def b(c=Depends(basic)):
        return {}

    @app.get("/c")
    def c(k=Depends(key)):
        return {}

    assert _auth(app, "GET", "/a") == (True, False, "bearer")
    assert _auth(app, "GET", "/b") == (True, False, "basic")
    assert _auth(app, "GET", "/c") == (True, False, "apikey:X-API-Key")


def test_guard_function_without_a_security_scheme_is_found_by_name():
    app = FastAPI()

    def require_admin(request=None):
        return True

    def get_db():
        return object()

    @app.post("/admin/thing")
    def thing(_=Depends(require_admin), db=Depends(get_db)):
        return {}

    @app.get("/plain")
    def plain(db=Depends(get_db)):
        return {}

    assert _auth(app, "POST", "/admin/thing")[0] is True
    assert _auth(app, "GET", "/plain")[0] is False


def test_explicit_marker_overrides_detection():
    app = FastAPI()

    def open_route():
        return {}

    open_route.__jscoup_requires_auth__ = True
    app.get("/marked")(open_route)

    assert _target(app, "GET", "/marked").requires_auth is True


# --- docs data: is the API public through the gateway? ----------------------------


def test_docs_data_tells_the_page_whether_a_target_is_public(tmp_path):
    from jscoup import JSCoup

    app = FastAPI()

    @app.get("/open")
    def open_():
        return {}

    @app.get("/closed")
    def closed():
        return {}

    bl = JSCoup(
        service_name="pub-test", db_path=str(tmp_path / "e.db"), gateway_enabled=True,
        gateway_db_path=str(tmp_path / "gw.db"), call_log_db_path=str(tmp_path / "c.db"),
        dashboard_session_db_path=str(tmp_path / "s.db"), dashboard_local_dev=True,
    )
    bl.registry.discover_fastapi(app)
    bl.gateway.set_public("http:GET:/open", True)

    items = {i["path"]: i for i in bl.dashboard._enrich_targets(bl.registry.to_list())}

    assert items["/open"]["public"] is True
    assert items["/closed"]["public"] is False
    bl.close()


# --- descriptions ------------------------------------------------------------------


def test_oauth2_form_fields_carry_fastapis_own_explanations():
    app = FastAPI()

    @app.post("/login")
    def login(form: OAuth2PasswordRequestForm = Depends()):
        return {}

    params = {p.name: p for p in _target(app, "POST", "/login").params}

    for name in ("grant_type", "username", "password", "scope", "client_id", "client_secret"):
        assert params[name].description, name
        assert len(params[name].description) <= 200
    assert "password" in params["grant_type"].description.lower()


def test_a_developers_own_description_is_kept_whole():
    from fastapi import Form

    app = FastAPI()
    text = "First sentence. Second sentence that must not be cut."

    @app.post("/signup")
    def signup(name: str = Form(..., description=text)):
        return {}

    params = {p.name: p for p in _target(app, "POST", "/signup").params}

    assert params["name"].description == text
