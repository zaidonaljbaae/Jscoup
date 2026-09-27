# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Tests for jscoup.registry.Registry — the target catalogue backing the
live tester and the gateway's per-user allowed-API list."""

import pytest

from jscoup.registry import Registry, Target


def test_add_manual_registers_an_http_target():
    registry = Registry()

    target = registry.add_manual("get", "/partner/orders", description="Partner order feed")

    assert target.id == "http:GET:/partner/orders"
    assert target.kind == "http"
    assert target.method == "GET"
    assert target.framework == "manual"
    assert registry.get("http:GET:/partner/orders") is target


def test_add_manual_defaults_name_from_method_and_path():
    registry = Registry()

    target = registry.add_manual("post", "/webhooks/stripe")

    assert target.name == "POST /webhooks/stripe"


def test_disable_hides_a_target_from_get_all_and_to_list():
    registry = Registry()
    registry.add(Target(id="http:GET:/x", kind="http", name="x", method="GET", path="/x"))

    disabled = registry.disable("http:GET:/x")

    assert disabled is True
    assert registry.get("http:GET:/x") is None
    assert registry.all() == []
    assert registry.to_list() == []
    assert registry.is_disabled("http:GET:/x") is True


def test_disable_unknown_target_returns_false():
    registry = Registry()

    assert registry.disable("http:GET:/nope") is False


def test_enable_reverses_a_disable():
    registry = Registry()
    registry.add(Target(id="http:GET:/x", kind="http", name="x", method="GET", path="/x"))
    registry.disable("http:GET:/x")

    registry.enable("http:GET:/x")

    assert registry.get("http:GET:/x") is not None
    assert registry.is_disabled("http:GET:/x") is False
    assert len(registry.all()) == 1


def test_disabled_target_survives_and_stays_hidden_across_rediscovery():
    """The real reason disabling has to be a separate set rather than just
    deleting from _targets: discover_flask/fastapi/django re-add every
    route on every dashboard request (see refresh_targets()), which would
    silently undo a plain delete on the very next request."""
    registry = Registry()
    registry.add(Target(id="http:GET:/x", kind="http", name="x", method="GET", path="/x"))
    registry.disable("http:GET:/x")

    # Simulate re-discovery re-adding the same route.
    registry.add(Target(id="http:GET:/x", kind="http", name="x", method="GET", path="/x"))

    assert registry.get("http:GET:/x") is None
    assert registry.all() == []


def test_include_disabled_still_lists_a_disabled_target_for_admin_management():
    """A disabled target is hidden from the gateway picker and live tester
    (the default), but the admin's own catalogue view must still be able to
    see and re-enable it — the default view is the only one that excludes it."""
    registry = Registry()
    registry.add(Target(id="http:GET:/x", kind="http", name="x", method="GET", path="/x"))
    registry.disable("http:GET:/x")

    visible = registry.to_list()
    everything = registry.to_list(include_disabled=True)

    assert visible == []
    assert len(everything) == 1
    assert everything[0]["id"] == "http:GET:/x"
    assert everything[0]["disabled"] is True


def test_to_list_reports_disabled_false_for_an_active_target():
    registry = Registry()
    registry.add(Target(id="http:GET:/x", kind="http", name="x", method="GET", path="/x"))

    assert registry.to_list()[0]["disabled"] is False


def test_manual_target_is_unaffected_by_disabling_a_different_target():
    registry = Registry()
    registry.add(Target(id="http:GET:/x", kind="http", name="x", method="GET", path="/x"))
    registry.add_manual("GET", "/y")

    registry.disable("http:GET:/x")

    ids = {t.id for t in registry.all()}
    assert ids == {"http:GET:/y"}


def test_set_description_overwrites_an_existing_targets_description():
    registry = Registry()
    registry.add(Target(id="http:GET:/x", kind="http", name="x", method="GET", path="/x", description="old"))

    registry.set_description("http:GET:/x", "Lists every widget for the caller's account")

    assert registry.get("http:GET:/x").description == "Lists every widget for the caller's account"


def test_set_description_survives_rediscovery():
    """Descriptions are set through the docs-page editor, but discover_flask()
    et al. re-add every route on every request (see refresh_targets()) — the
    override has to outlive that re-add the same way disabling does."""
    registry = Registry()
    registry.add(Target(id="http:GET:/x", kind="http", name="x", method="GET", path="/x"))

    registry.set_description("http:GET:/x", "Rediscovery-proof description")
    registry.add(Target(id="http:GET:/x", kind="http", name="x", method="GET", path="/x"))

    assert registry.get("http:GET:/x").description == "Rediscovery-proof description"


def test_set_description_for_a_not_yet_discovered_target_applies_once_it_appears():
    registry = Registry()

    registry.set_description("http:GET:/later", "Set before the route was ever registered")
    registry.add(Target(id="http:GET:/later", kind="http", name="later", method="GET", path="/later"))

    assert registry.get("http:GET:/later").description == "Set before the route was ever registered"


def test_discover_flask_reads_the_int_converter_as_the_params_type():
    flask = pytest.importorskip("flask")
    app = flask.Flask(__name__)

    @app.get("/items/<int:item_id>")
    def get_item(item_id):
        return {}

    registry = Registry()
    registry.discover_flask(app)

    target = registry.get("http:GET:/items/<int:item_id>")
    assert target.params[0].name == "item_id"
    assert target.params[0].type == "int"


def test_discover_flask_defaults_an_untyped_converter_to_string():
    flask = pytest.importorskip("flask")
    app = flask.Flask(__name__)

    @app.get("/pages/<slug>")
    def get_page(slug):
        return {}

    registry = Registry()
    registry.discover_flask(app)

    target = registry.get("http:GET:/pages/<slug>")
    assert target.params[0].type == "string"


def test_django_view_body_keys_read_through_a_constant_loop_are_detected():
    from jscoup.registry import _django_view_info

    def update_room(request, room_id):
        data = request.POST
        for field in ("number", "is_clean"):
            if field in data:
                print(data[field])
        return data["extra"]

    methods, query, body = _django_view_info(update_room)

    by_name = {p.name: p for p in body}
    assert set(by_name) == {"number", "is_clean", "extra"}
    assert by_name["number"].required is False
    assert by_name["extra"].required is True


def test_flask_routes_behind_guard_decorators_are_flagged_as_protected():
    import functools

    from flask import Flask

    def make_group_guard(name):  # like Flask-Authorize's ``authorize.in_group("admin")``
        def deco(fn):
            @functools.wraps(fn)
            def wrapper(*a, **k):
                return fn(*a, **k)
            return wrapper
        return deco

    class authorize:
        in_group = staticmethod(make_group_guard)

    def login_required(fn):
        @functools.wraps(fn)
        def wrapper(*a, **k):
            return fn(*a, **k)
        return wrapper

    def csrf_protect(fn):
        @functools.wraps(fn)
        def wrapper(*a, **k):
            return fn(*a, **k)
        return wrapper

    app = Flask(__name__)

    @app.route("/admin/list")
    @authorize.in_group("admin")
    def list_things():
        return "x"

    @app.route("/me")
    @login_required
    def profile():
        return "x"

    @app.route("/form", methods=["POST"])
    @csrf_protect
    def submit_form():
        return "x"

    @app.route("/open")
    def health_check():
        return "x"

    registry = Registry()
    registry.discover_flask(app)

    needs = {t.path: t.requires_auth for t in registry.all()}
    assert needs == {"/admin/list": True, "/me": True, "/form": False, "/open": False}


def test_guard_decorator_is_found_even_when_an_outer_decorator_drops_wrapped():
    """Some validators wrap the view without functools.wraps/__wrapped__, so the
    original function is only reachable through the wrapper's closure."""
    from flask import Flask

    def validate(fn):  # no functools.wraps, no __wrapped__
        def nested(**kwargs):
            return fn(**kwargs)
        nested.__name__ = fn.__name__
        return nested

    def guard(fn):
        def outer(**kwargs):
            return fn(**kwargs)
        outer.__name__ = fn.__name__
        return outer

    class authorize:
        @staticmethod
        def in_group(name):
            return guard

    app = Flask(__name__)

    @app.route("/orders")
    @authorize.in_group("admin")
    @validate
    def list_orders():
        return "x"

    @app.route("/status")
    @validate
    def get_status():
        return "x"

    registry = Registry()
    registry.discover_flask(app)

    assert {t.path: t.requires_auth for t in registry.all()} == {"/orders": True, "/status": False}


def test_targets_report_the_file_their_function_is_defined_in_even_through_wrappers():
    import functools

    from flask import Flask

    def wrap(fn):  # a wrapper defined in *this* file, hiding the view under another name
        @functools.wraps(fn)
        def wrapper(*a, **k):
            return fn(*a, **k)
        return wrapper

    app = Flask(__name__)

    @app.route("/things")
    @wrap
    def list_things():
        return "x"

    registry = Registry()
    registry.discover_flask(app)
    registry.register_callable(lambda: None, name="job")

    files = {t.id: t.source_file for t in registry.all()}
    assert files["http:GET:/things"] == "test_registry.py"
    assert files["service:job"] == "test_registry.py"
    assert registry.get("http:GET:/things").to_dict()["source_file"] == "test_registry.py"


def test_source_file_ignores_a_wrapper_defined_in_another_file_of_the_same_app():
    """A ``@token_required`` living in ``api_auth.py`` wraps views from ``views.py``;
    the API belongs to views.py, not to the file holding the wrapper."""
    import functools

    from flask import Flask

    wrapper_source = """
def token_required(fn):
    @functools.wraps(fn)
    def wrapper(*a, **k):
        return fn(*a, **k)
    return wrapper
"""
    namespace = {"functools": functools}
    exec(compile(wrapper_source, "/project/api_auth.py", "exec"), namespace)

    app = Flask(__name__)

    @app.route("/rooms")
    @namespace["token_required"]
    def rooms():
        return "x"

    registry = Registry()
    registry.discover_flask(app)

    assert registry.get("http:GET:/rooms").source_file == "test_registry.py"



# --------------------------------------------------------------------------- #
# parameters a Flask view reads (validator declarations and direct request use)
# --------------------------------------------------------------------------- #


def _fake_validator(source):
    """Shaped like flask_parameter_validation's ``Query``/``Json``/``Route`` markers
    (module + a ``name`` naming where the value comes from), without needing the package."""
    def init(self, default=None, **limits):
        self.default = default
        for key, value in limits.items():
            setattr(self, key, value)

    return type(source.capitalize(), (), {
        "name": source, "__init__": init,
        "__module__": "flask_parameter_validation.parameter_types." + source,
    })


def _params_of(registry, method, path):
    target = registry.get(f"http:{method}:{path}")
    return {p.name: p for p in target.params}


def test_flask_view_parameters_declared_with_validator_markers_are_detected():
    from typing import Optional

    from flask import Flask

    Query, Json, Route = _fake_validator("query"), _fake_validator("json"), _fake_validator("route")

    def validate(fn):  # a validator that wraps WITHOUT __wrapped__, like the real one
        def nested(**kwargs):
            return fn(**kwargs)
        nested.__name__ = fn.__name__
        return nested

    app = Flask(__name__)

    @app.route("/orders/<string:order_id>", methods=["PUT"])
    @validate
    def update_order(order_id: str = Route(max_str_length=60),
                     status: Optional[str] = Json(max_str_length=20),
                     qty: int = Json(min_int=1, max_int=99)):
        return "x"

    @app.route("/orders")
    @validate
    def list_orders(customer: str = Query(min_str_length=1, max_str_length=60),
                    page: int = Query(default=1)):
        return "x"

    registry = Registry()
    registry.discover_flask(app)

    put = _params_of(registry, "PUT", "/orders/<string:order_id>")
    assert (put["order_id"].location, put["order_id"].description) == ("path", "at most 60 characters")
    assert (put["status"].location, put["status"].required) == ("body", False)
    assert (put["qty"].location, put["qty"].type, put["qty"].required) == ("body", "int", True)
    assert put["qty"].description == "between 1 and 99"

    get = _params_of(registry, "GET", "/orders")
    assert (get["customer"].location, get["customer"].required) == ("query", True)
    assert get["customer"].description == "1-60 characters"
    assert (get["page"].required, get["page"].default, get["page"].type) == (False, 1, "int")


def test_a_get_route_never_gets_body_parameters():
    from flask import Flask

    Json = _fake_validator("json")
    app = Flask(__name__)

    @app.route("/thing", methods=["GET", "POST"])
    def thing(payload: str = Json()):
        return "x"

    registry = Registry()
    registry.discover_flask(app)

    assert "payload" not in _params_of(registry, "GET", "/thing")
    assert _params_of(registry, "POST", "/thing")["payload"].location == "body"


def test_flask_view_parameters_read_straight_from_the_request_are_detected():
    from flask import Flask, request

    app = Flask(__name__)

    @app.route("/report")
    def report():
        status = request.args.get("status", default="OPEN")
        limit = request.args.get("limit", type=int)
        return f"{status}{limit}"

    @app.route("/upload", methods=["POST"])
    def upload():
        data = request.get_json()
        return f"{data['name']}{data.get('note')}{request.files['doc']}{request.form.get('kind')}"

    registry = Registry()
    registry.discover_flask(app)

    report_params = _params_of(registry, "GET", "/report")
    assert (report_params["status"].location, report_params["status"].default, report_params["status"].required) == ("query", "OPEN", False)
    assert (report_params["limit"].type, report_params["limit"].required) == ("int", False)

    upload_params = _params_of(registry, "POST", "/upload")
    assert (upload_params["name"].location, upload_params["name"].required) == ("body", True)
    assert (upload_params["note"].location, upload_params["note"].required) == ("body", False)
    assert upload_params["doc"].type == "file"
    assert upload_params["kind"].location == "form"


def test_flask_parameter_validation_package_declarations_are_detected():
    """The same, against the real package when it is installed."""
    import pytest

    fpv = pytest.importorskip("flask_parameter_validation")
    from typing import Optional

    from flask import Flask

    app = Flask(__name__)

    @app.route("/items")
    @fpv.ValidateParameters()
    def list_items(code: str = fpv.Query(min_str_length=1, max_str_length=10),
                   page: Optional[int] = fpv.Query(default=1)):
        return "x"

    @app.route("/items", methods=["POST"])
    @fpv.ValidateParameters()
    def add_item(name: str = fpv.Json(), note: Optional[str] = fpv.Json()):
        return "x"

    registry = Registry()
    registry.discover_flask(app)

    got = _params_of(registry, "GET", "/items")
    assert (got["code"].location, got["code"].required, got["code"].description) == ("query", True, "1-10 characters")
    assert (got["page"].required, got["page"].type) == (False, "int")
    posted = _params_of(registry, "POST", "/items")
    assert (posted["name"].location, posted["name"].required) == ("body", True)
    assert posted["note"].required is False
