# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Registry of everything the dashboard can invoke live.

Two kinds of targets exist:

``http``
    An endpoint discovered from the web framework. Replayed over HTTP against
    the running server, so middleware, auth and serialisation all run for real.

``service``
    A plain Python callable registered with ``@jscoup.watch`` (a service, a
    task, a Lambda handler). Called directly in-process with the parameters
    typed in the dashboard.
"""

from __future__ import annotations

import inspect
import re
import typing
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

_PATH_PARAM = re.compile(r"[<{]([^>}:]+)(?::[^>}]+)?[>}]")
_FLASK_PARAM = re.compile(r"<(?:([a-zA-Z_][a-zA-Z0-9_]*):)?([^<>]+)>")
# Werkzeug's built-in path converters, mapped to the same short type names
# _annotation_name() would produce from a real Python type hint.
_FLASK_CONVERTER_TYPES = {"int": "int", "float": "float", "uuid": "uuid"}


@dataclass
class ParamSpec:
    name: str
    location: str = "body"  # path | query | body | argument
    type: str = "string"
    required: bool = True
    default: Any = None
    description: str = ""
    # A developer-supplied example (see JSCoup.describe(params_example=...));
    # None means "derive one automatically" — see jscoup.examples.
    example: Any = None
    # Allowed values (Literal / Enum) and validation rules (pattern, ge, le,
    # min_length...) the framework declares for this input, when known.
    choices: List[Any] = field(default_factory=list)
    constraints: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        from .examples import sample_value

        data = asdict(self)
        if data["example"] is None:
            if self.choices:
                data["example"] = self.choices[0]
            elif not self.required and self.default is None and self.location in ("query", "form", "body"):
                # An optional input with no default is left empty rather than
                # pre-filled with a made-up value that the API might reject.
                data["example"] = ""
            else:
                data["example"] = sample_value(self.name, self.type, self.default)
        return data


@dataclass
class Target:
    """One invokable unit."""

    id: str
    kind: str  # http | service
    name: str
    method: str = "GET"
    path: str = ""
    description: str = ""
    full_description: str = ""
    params: List[ParamSpec] = field(default_factory=list)
    requires_auth: bool = False
    # How the endpoint authenticates ("bearer", "basic", "apikey:<name>"...) and
    # whether a token is accepted but not required (auto_error=False schemes).
    auth_scheme: str = ""
    auth_optional: bool = False
    tags: List[str] = field(default_factory=list)
    framework: str = ""
    # The source file the endpoint's own function is defined in (basename, e.g.
    # "pedido_api.py"). The Live Tester groups APIs by it.
    source_file: str = ""
    func: Optional[Callable[..., Any]] = None
    is_async: bool = False
    # Off by default; check_apis()'s sweep only calls a target explicitly
    # opted in via healthcheck_allowed=True.
    healthcheck_allowed: bool = False
    # Developer overrides (JSCoup.describe): a hand-written JSON request body,
    # and a hand-written response body per status code. Anything left unset is
    # derived automatically — see jscoup.examples.
    request_example: Any = None
    response_examples: Dict[int, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        from .examples import request_body_example

        data = {
            "request_example": (
                self.request_example if self.request_example is not None else request_body_example(self.params)
            ),
            "id": self.id,
            "kind": self.kind,
            "name": self.name,
            "method": self.method,
            "path": self.path,
            "description": self.description,
            "full_description": self.full_description,
            "params": [p.to_dict() for p in self.params],
            "requires_auth": self.requires_auth,
            "auth_scheme": self.auth_scheme,
            "auth_optional": self.auth_optional,
            "tags": self.tags,
            "framework": self.framework,
            "source_file": self.source_file,
            "is_async": self.is_async,
            "healthcheck_allowed": self.healthcheck_allowed,
        }
        return data


class Registry:
    """Holds targets and discovers them from the installed framework."""

    def __init__(self) -> None:
        self._targets: Dict[str, Target] = {}
        self._overrides: Dict[str, Dict[str, Any]] = {}
        self._disabled: set = set()
        # Side index keyed by (method, path): _targets keeps only one Target
        # per id, so a same-(method, path) collision would otherwise be lost
        # the moment the losing registration is overwritten. This keeps every
        # distinct name seen at a given (method, path) so http_collisions()
        # can report it.
        self._http_by_key: Dict[Tuple[str, str], Dict[str, Target]] = {}

    # -- basic API ---------------------------------------------------------- #

    def add(self, target: Target) -> Target:
        override = self._overrides.get(target.id)
        if override:
            if "description" in override:
                target.description = override["description"]
            if "full_description" in override:
                target.full_description = override["full_description"]
            if "tags" in override:
                target.tags = override["tags"]
            if "healthcheck_allowed" in override:
                target.healthcheck_allowed = override["healthcheck_allowed"]
            if "request_example" in override:
                target.request_example = override["request_example"]
            if "response_examples" in override:
                target.response_examples = dict(override["response_examples"])
            param_docs = override.get("params")
            if param_docs:
                for p in target.params:
                    if p.name in param_docs:
                        p.description = param_docs[p.name]
            param_examples = override.get("params_example")
            if param_examples:
                for p in target.params:
                    if p.name in param_examples:
                        p.example = param_examples[p.name]
        self._targets[target.id] = target
        if target.kind == "http":
            self._http_by_key.setdefault((target.method, target.path), {})[target.name] = target
        return target

    def http_collisions(self) -> Dict[Tuple[str, str], List[Target]]:
        """Every ``(method, path)`` currently claimed by more than one
        distinct registration."""
        return {key: list(bucket.values()) for key, bucket in self._http_by_key.items() if len(bucket) > 1}

    def describe(
        self,
        *,
        method: Optional[str] = None,
        path: Optional[str] = None,
        name: Optional[str] = None,
        description: Optional[str] = None,
        full_description: Optional[str] = None,
        params: Optional[Dict[str, str]] = None,
        tags: Optional[List[str]] = None,
        healthcheck_allowed: Optional[bool] = None,
        request_example: Any = None,
        response_examples: Optional[Dict[int, Any]] = None,
        params_example: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Attach a hand-written description to an API or service, independent
        of whatever the framework auto-discovered.

        Pass ``method`` + ``path`` for an HTTP target or ``name`` for a
        ``@jscoup.watch``-registered service. Survives re-discovery, so it
        can be called once, at any point, regardless of import order.

        ``request_example`` is a JSON body example, ``response_examples`` maps
        a status code to the body shown for it, and ``params_example`` maps a
        parameter name to its example value — anything not given here is
        derived automatically (see :mod:`jscoup.examples`).
        """
        if method and path:
            key = f"http:{method.upper()}:{path}"
        elif name:
            key = f"service:{name}"
        else:
            raise ValueError("describe() needs either method+path or name")
        override = self._overrides.setdefault(key, {})
        if description is not None:
            override["description"] = description
        if full_description is not None:
            override["full_description"] = full_description
        if params:
            override.setdefault("params", {}).update(params)
        if tags is not None:
            override["tags"] = tags
        if healthcheck_allowed is not None:
            override["healthcheck_allowed"] = healthcheck_allowed
        if request_example is not None:
            override["request_example"] = request_example
        if response_examples:
            override.setdefault("response_examples", {}).update(response_examples)
        if params_example:
            override.setdefault("params_example", {}).update(params_example)
        existing = self._targets.get(key)
        if existing is not None:
            self.add(existing)

    def get(self, target_id: str) -> Optional[Target]:
        if target_id in self._disabled:
            return None
        return self._targets.get(target_id)

    def all(self, include_disabled: bool = False) -> List[Target]:
        source = self._targets.values() if include_disabled else (
            t for t in self._targets.values() if t.id not in self._disabled
        )
        return sorted(source, key=lambda t: (t.kind, t.path or t.name))

    def clear(self) -> None:
        self._targets.clear()

    def to_list(self, include_disabled: bool = False) -> List[Dict[str, Any]]:
        """``include_disabled=True`` is for the admin's own API-catalogue
        management view — it needs to see and re-enable a hidden target,
        which the gateway picker and live tester (the default) must not."""
        return [
            dict(t.to_dict(), disabled=t.id in self._disabled)
            for t in self.all(include_disabled=include_disabled)
        ]

    def set_description(self, target_id: str, description: str) -> None:
        """Overwrite a target's description by id — the same override
        ``describe()`` writes, addressed directly by id instead of by
        method+path/name, for a caller that already has the id (the
        dashboard's own API-catalogue editor)."""
        override = self._overrides.setdefault(target_id, {})
        override["description"] = description
        existing = self._targets.get(target_id)
        if existing is not None:
            self.add(existing)

    def add_manual(
        self,
        method: str,
        path: str,
        name: Optional[str] = None,
        description: str = "",
        tags: Optional[List[str]] = None,
    ) -> Target:
        """Register an HTTP target that isn't discovered from the framework
        — a manually catalogued API, replayed the same way as any other
        ``kind="http"`` target. Unaffected by re-discovery, since discovery
        only touches ids belonging to its own framework's routes."""
        method = method.upper()
        target = Target(
            id=f"http:{method}:{path}",
            kind="http",
            name=name or f"{method} {path}",
            method=method,
            path=path,
            description=description,
            tags=tags or [],
            framework="manual",
        )
        return self.add(target)

    def disable(self, target_id: str) -> bool:
        """Hide a target from listings, the live tester and the gateway,
        and make it unresolvable via :meth:`get` — persists across
        re-discovery, since discovery re-adds to ``_targets`` but never
        touches this set. Returns False if the id is unknown."""
        if target_id not in self._targets:
            return False
        self._disabled.add(target_id)
        return True

    def enable(self, target_id: str) -> None:
        self._disabled.discard(target_id)

    def is_disabled(self, target_id: str) -> bool:
        return target_id in self._disabled

    def exists(self, target_id: str) -> bool:
        """True if a target is registered at all, disabled or not — unlike
        :meth:`get`, which treats a disabled target as absent."""
        return target_id in self._targets

    def sync_disabled(self, disabled_ids: Any) -> None:
        """Replace the disabled set with the current cross-process truth
        (see :meth:`~jscoup.gateway.GatewayStore.disabled_target_ids`),
        limited to targets this process actually knows about."""
        self._disabled = {tid for tid in disabled_ids if tid in self._targets}

    # -- callables ---------------------------------------------------------- #

    def register_callable(
        self,
        func: Callable[..., Any],
        name: Optional[str] = None,
        kind: str = "service",
        description: str = "",
        tags: Optional[List[str]] = None,
        healthcheck_allowed: bool = False,
    ) -> Target:
        name = name or f"{func.__module__}.{func.__qualname__}"
        params: List[ParamSpec] = []
        try:
            signature = inspect.signature(func)
        except (TypeError, ValueError):  # builtins
            signature = None
        if signature:
            for param in signature.parameters.values():
                if param.kind in (param.VAR_POSITIONAL, param.VAR_KEYWORD):
                    continue
                if param.name in ("self", "cls"):
                    continue  # a class-method target (watch_class/watch_module) — not caller input
                params.append(
                    ParamSpec(
                        name=param.name,
                        location="argument",
                        type=_annotation_name(param.annotation),
                        required=param.default is inspect.Parameter.empty,
                        default=None if param.default is inspect.Parameter.empty else _safe(param.default),
                    )
                )
        target = Target(
            id=f"service:{name}",
            kind="service",
            name=name,
            method="CALL",
            path="",
            description=description or (inspect.getdoc(func) or "").split("\n")[0],
            params=params,
            tags=tags or [],
            func=func,
            is_async=inspect.iscoroutinefunction(func),
            framework=kind,
            source_file=_source_file(func),
            healthcheck_allowed=healthcheck_allowed,
        )
        return self.add(target)

    # -- framework discovery ------------------------------------------------ #

    def discover_flask(self, app: Any, mount_path: str = "") -> int:
        found = 0
        for rule in app.url_map.iter_rules():
            path = str(rule.rule)
            if path.startswith("/static") or (mount_path and path.startswith(mount_path)):
                continue
            methods = sorted((rule.methods or set()) - {"HEAD", "OPTIONS"})
            for method in methods:
                view = app.view_functions.get(rule.endpoint)
                params = [
                    ParamSpec(name=n, location="path", type=_FLASK_CONVERTER_TYPES.get(conv, "string"), required=True)
                    for conv, n in _FLASK_PARAM.findall(path)
                ]
                params = _merge_flask_params(params, view, method)
                self.add(
                    Target(
                        id=f"http:{method}:{path}",
                        kind="http",
                        name=rule.endpoint,
                        method=method,
                        path=path,
                        description=(inspect.getdoc(view) or "").split("\n")[0] if view else "",
                        params=params,
                        requires_auth=_guess_auth(view),
                        framework="flask",
                        source_file=_source_file(view),
                    )
                )
                found += 1
        return found

    def discover_fastapi(self, app: Any, mount_path: str = "") -> int:
        found = 0
        for route in _iter_fastapi_routes(app):
            path = getattr(route, "path", "")
            endpoint = getattr(route, "endpoint", None)
            if not path or endpoint is None:
                continue
            if path.startswith("/openapi") or path.startswith("/docs") or path.startswith("/redoc"):
                continue
            if mount_path and path.startswith(mount_path):
                continue
            doc = inspect.getdoc(endpoint) or ""
            for method in sorted((getattr(route, "methods", set()) or set()) - {"HEAD", "OPTIONS"}):
                params = [
                    ParamSpec(name=n, location="path", type="string", required=True)
                    for n in _PATH_PARAM.findall(path)
                ]
                params += _fastapi_signature_params(endpoint, {p.name for p in params})
                _fastapi_refine_own_params(params, route)
                params += _fastapi_dependency_params(route, {p.name for p in params})
                auth = _fastapi_auth_info(route)
                marker = getattr(endpoint, "__jscoup_requires_auth__", None)
                if marker is not None:
                    requires_auth, auth_optional, auth_scheme = bool(marker), False, ("bearer" if marker else "")
                elif auth is not None:
                    requires_auth, auth_optional, auth_scheme = auth
                else:
                    requires_auth, auth_optional, auth_scheme = _guess_auth(endpoint), False, ""
                self.add(
                    Target(
                        id=f"http:{method}:{path}",
                        kind="http",
                        name=getattr(route, "name", path),
                        method=method,
                        path=path,
                        description=(getattr(route, "summary", "") or doc.split("\n")[0]),
                        full_description=(getattr(route, "description", "") or doc),
                        params=params,
                        requires_auth=requires_auth,
                        auth_scheme=auth_scheme,
                        auth_optional=auth_optional,
                        source_file=_source_file(endpoint),
                        tags=[str(t) for t in (getattr(route, "tags", None) or [])],
                        framework="fastapi",
                    )
                )
                found += 1
        return found

    def discover_django(self, mount_path: str = "") -> int:
        from django.urls import get_resolver  # type: ignore

        found = 0

        def walk(resolver, prefix: str = "", inherited=()) -> None:
            nonlocal found
            for pattern in resolver.url_patterns:
                route = prefix + str(getattr(pattern.pattern, "_route", pattern.pattern))
                names = tuple(dict.fromkeys((*inherited, *getattr(pattern.pattern, "converters", {}), *pattern.pattern.regex.groupindex)))
                if hasattr(pattern, "url_patterns"):
                    walk(pattern, route, names)
                    continue
                path = "/" + route.lstrip("/")
                marker = (mount_path or "").strip("/")
                if marker and marker in path:
                    continue
                params = [
                    ParamSpec(name=n, location="path", type="string", required=True)
                    for n in names
                ]
                callback = getattr(pattern, "callback", None)
                converters = getattr(pattern.pattern, "converters", {}) or {}
                for spec in params:
                    conv = converters.get(spec.name)
                    if conv is not None:
                        kind = type(conv).__name__.lower().replace("converter", "")
                        spec.type = {"int": "int", "str": "string", "slug": "string", "uuid": "string", "path": "string"}.get(kind, spec.type)
                methods, query_params, body_params = _django_view_info(callback)
                description = (inspect.getdoc(callback) or "").split("\n")[0] if callback else ""
                name = getattr(pattern, "name", None) or path
                for method in (methods or [None]):
                    extra = list(query_params)
                    if method in {"POST", "PUT", "PATCH"}:
                        extra += body_params
                    seen_names = {p.name for p in params}
                    all_params = params + [p for p in extra if p.name not in seen_names]
                    self.add(
                        Target(
                            id=f"http:{method or 'ANY'}:{path}",
                            kind="http",
                            name=name if not methods or len(methods) == 1 else f"{name} ({method})",
                            method=method or "GET",
                            path=path,
                            description=description,
                            params=all_params,
                            requires_auth=_guess_auth(callback),
                            framework="django",
                            source_file=_source_file(callback),
                        )
                    )
                found += 1

        walk(get_resolver())
        return found


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #



_BODY_METHODS = {"POST", "PUT", "PATCH"}
_HTTP_DECORATORS = {"require_GET": ["GET"], "require_POST": ["POST"], "require_safe": ["GET", "HEAD"]}


def _django_view_info(callback: Any):
    """Read a Django view's own source to find which HTTP methods it allows
    and which query/body/file parameters it reads — Django views declare
    none of this in a signature. Returns ``(methods, query_params, body_params)``;
    all empty when the source can't be read."""
    import ast
    import textwrap

    if callback is None:
        return [], [], []
    view_class = getattr(callback, "view_class", None) or getattr(callback, "cls", None)
    if view_class is not None:
        methods = [m.upper() for m in ("get", "post", "put", "patch", "delete") if hasattr(view_class, m)]
        return methods, [], []
    inner = callback
    while getattr(inner, "__wrapped__", None) is not None:
        inner = inner.__wrapped__
    try:
        tree = ast.parse(textwrap.dedent(inspect.getsource(inner)))
    except (OSError, TypeError, SyntaxError, IndentationError):
        return [], [], []
    func = next((n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))), None)
    if func is None:
        return [], [], []

    methods: List[str] = []
    for dec in func.decorator_list:
        target = dec.func if isinstance(dec, ast.Call) else dec
        dec_name = target.id if isinstance(target, ast.Name) else getattr(target, "attr", "")
        if dec_name == "require_http_methods" and isinstance(dec, ast.Call) and dec.args:
            arg = dec.args[0]
            if isinstance(arg, (ast.List, ast.Tuple, ast.Set)):
                methods += [str(e.value).upper() for e in arg.elts if isinstance(e, ast.Constant)]
        elif dec_name in _HTTP_DECORATORS:
            methods += _HTTP_DECORATORS[dec_name]
    methods = list(dict.fromkeys(methods))

    request_arg = func.args.args[0].arg if func.args.args else "request"

    def is_request(node: Any) -> bool:
        return isinstance(node, ast.Name) and node.id == request_arg

    def request_attr(node: Any) -> str:
        if isinstance(node, ast.Attribute) and is_request(node.value):
            return node.attr
        return ""

    def source_kind(node: Any) -> str:
        """'query' / 'body' / 'files' when the expression is a request payload."""
        attr = request_attr(node)
        if attr == "GET":
            return "query"
        if attr in ("POST", "data"):
            return "body"
        if attr == "FILES":
            return "files"
        if isinstance(node, ast.Call):
            fname = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", "")
            touches_request = any(is_request(a) or request_attr(a) == "body" for a in node.args) or any(
                request_attr(n) == "body" for n in ast.walk(node)
            )
            if touches_request and (fname.lower().find("body") >= 0 or fname.lower().find("json") >= 0
                                    or fname.lower().find("payload") >= 0 or fname == "loads"):
                return "body"
        return ""

    variables: Dict[str, str] = {}
    for node in ast.walk(func):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            kind = source_kind(node.value)
            if kind:
                variables[node.targets[0].id] = kind

    def kind_of(node: Any) -> str:
        if isinstance(node, ast.Name):
            return variables.get(node.id, "")
        return source_kind(node)

    parents: Dict[Any, Any] = {}
    for node in ast.walk(func):
        for child in ast.iter_child_nodes(node):
            parents[child] = node

    found: Dict[tuple, ParamSpec] = {}

    def record(kind: str, name: str, required: bool, default: Any, node: Any) -> None:
        type_name = "string"
        parent = parents.get(node)
        if isinstance(parent, ast.Call) and isinstance(parent.func, ast.Name) and parent.func.id in ("int", "float", "bool", "str"):
            type_name = {"int": "int", "float": "float", "bool": "bool", "str": "string"}[parent.func.id]
        elif isinstance(default, bool):
            type_name = "bool"
        elif isinstance(default, int):
            type_name = "int"
        elif isinstance(default, float):
            type_name = "float"
        if kind == "files":
            type_name = "file"
        location = "query" if kind == "query" else "body"
        key = (location, name)
        if key in found:
            found[key].required = found[key].required or required
            return
        found[key] = ParamSpec(
            name=name, location=location, type=type_name, required=required,
            default=default if isinstance(default, (str, int, float, bool)) else None,
        )

    # ``for field in ("a", "b"): ... data[field]`` reads a fixed set of keys.
    loop_keys: Dict[str, List[str]] = {}
    for node in ast.walk(func):
        if (isinstance(node, ast.For) and isinstance(node.target, ast.Name)
                and isinstance(node.iter, (ast.Tuple, ast.List, ast.Set))
                and node.iter.elts
                and all(isinstance(e, ast.Constant) and isinstance(e.value, str) for e in node.iter.elts)):
            loop_keys[node.target.id] = [e.value for e in node.iter.elts]

    for node in ast.walk(func):
        if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Name) and node.slice.id in loop_keys:
            kind = kind_of(node.value)
            if kind and isinstance(node.ctx, ast.Load):
                for key in loop_keys[node.slice.id]:
                    record(kind, key, False, None, node)  # loops usually guard with ``if key in data``
        elif isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
            kind = kind_of(node.value)
            if kind and isinstance(node.ctx, ast.Load):
                record(kind, node.slice.value, True, None, node)
        elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get"
              and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)):
            kind = kind_of(node.func.value)
            if kind:
                default = node.args[1].value if len(node.args) > 1 and isinstance(node.args[1], ast.Constant) else None
                record(kind, node.args[0].value, False, default, node)

    query = [p for (loc, _), p in found.items() if loc == "query"]
    body = [p for (loc, _), p in found.items() if loc == "body"]
    return methods, query, body


def _iter_fastapi_routes(app: Any):
    """Yield flat, leaf route-like objects (each exposing .path/.endpoint/.methods).

    On newer Starlette versions, ``app.include_router(...)`` is represented
    by a router-inclusion wrapper exposing ``effective_route_contexts()``
    instead of ``.path``/``.endpoint`` directly; detected by duck typing so
    this works across Starlette versions.
    """
    for route in getattr(app, "routes", []):
        if hasattr(route, "effective_route_contexts"):
            yield from route.effective_route_contexts()
        else:
            yield route


def _annotation_name(annotation: Any) -> str:
    """Render a type hint as a short, human string: ``Optional[int]`` -> "int",
    ``List[str]`` -> "list[str]", a plain class -> its name."""
    if annotation is inspect.Parameter.empty or annotation is None:
        return "any"
    origin = getattr(annotation, "__origin__", None)
    if origin is not None:
        args = [a for a in getattr(annotation, "__args__", ()) if a is not type(None)]  # noqa: E721
        if origin is Union:
            if len(args) == 1:
                return _annotation_name(args[0])
            return " | ".join(_annotation_name(a) for a in args) or "any"
        name = getattr(origin, "__name__", str(origin)).lower()
        return f"{name}[{', '.join(_annotation_name(a) for a in args)}]" if args else name
    return getattr(annotation, "__name__", str(annotation))


def _is_fastapi_dependency(default: Any) -> bool:
    """True for a parameter whose default is ``fastapi.Depends(...)``, i.e.
    supplied by FastAPI's DI system rather than the caller. Duck-typed on
    ``.dependency`` so this needs no hard dependency on fastapi."""
    return hasattr(default, "dependency")


def _is_pydantic_model(annotation: Any) -> bool:
    return isinstance(annotation, type) and (
        hasattr(annotation, "model_fields") or hasattr(annotation, "__fields__")
    )


def _expand_pydantic_params(model: Any, location: str) -> Optional[List["ParamSpec"]]:
    """Expand a Pydantic request-body model into one ParamSpec per field.
    Returns ``None`` if ``model`` isn't a Pydantic model it can introspect;
    never raises.
    """
    try:
        if hasattr(model, "model_fields"):  # pydantic v2
            params = []
            for name, info in model.model_fields.items():
                try:
                    required = info.is_required()
                except Exception:
                    required = info.default is None
                default = None if required else _safe(getattr(info, "default", None))
                params.append(
                    ParamSpec(
                        name=name,
                        location=location,
                        type=_annotation_name(getattr(info, "annotation", None)),
                        required=required,
                        default=default,
                        description=getattr(info, "description", None) or "",
                    )
                )
            return params
        if hasattr(model, "__fields__"):  # pydantic v1
            params = []
            for name, info in model.__fields__.items():
                field_info = getattr(info, "field_info", None)
                required = bool(getattr(info, "required", True))
                default = None if required else _safe(getattr(info, "default", None))
                params.append(
                    ParamSpec(
                        name=name,
                        location=location,
                        type=_annotation_name(getattr(info, "outer_type_", None)),
                        required=required,
                        default=default,
                        description=(getattr(field_info, "description", "") or "") if field_info else "",
                    )
                )
            return params
    except Exception:
        return None
    return None


def _safe(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return repr(value)


def _guess_auth(view: Any) -> bool:
    """Heuristic: does this view sit behind an auth decorator?"""
    if view is None:
        return False
    names = {getattr(view, "__name__", ""), getattr(view, "__qualname__", "")}
    wrapped = getattr(view, "__wrapped__", None)
    while wrapped is not None:
        names.add(getattr(wrapped, "__name__", ""))
        wrapped = getattr(wrapped, "__wrapped__", None)
    marker = getattr(view, "__jscoup_requires_auth__", None)
    if marker is not None:
        return bool(marker)
    doc = (inspect.getdoc(view) or "").lower()
    return (
        any(word in doc for word in ("requires token", "requires auth", "authenticated"))
        or any("auth" in n.lower() or "token" in n.lower() for n in names if n)
        or _has_auth_decorator(view)
    )


# Decorator names that put a view behind a login/token/permission check
# (``@authorize.in_group("admin")``, ``@login_required``, ``@jwt_required()``,
# ``@permission_required(...)``, ``@token_required``...). Matched against the
# lower-cased dotted name. CSRF decorators are excluded: ``csrf_protect`` is not
# a login check.
_AUTH_DECORATOR_HINTS = (
    "auth", "login_required", "login_requir", "jwt", "token", "bearer", "cognito", "oauth",
    "permission", "roles_required", "role_required", "roles_accepted", "has_role", "in_group",
    "protected", "secure", "api_key", "apikey",
)


def _original_function(view: Any) -> Any:
    """The endpoint's own function, looked up through its decorators.

    Decorators wrap the view, and a wrapper can sit in a third-party package
    (a validator) *or* in the app's own code (``api_auth.py``'s
    ``@token_required``). ``functools.wraps`` copies the original's
    ``__module__`` onto the wrapper, so the original is the reachable function
    whose own file is the file of the module it claims to belong to; a wrapper
    defined elsewhere doesn't match. Returns ``None`` when nothing qualifies."""
    import os
    import sys

    jscoup_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = []
    for fn in _reachable_functions(view):
        path = getattr(getattr(fn, "__code__", None), "co_filename", "") or ""
        norm = path.replace("\\", "/").lower()
        if not path or "site-packages" in norm or "dist-packages" in norm or os.path.abspath(path).startswith(jscoup_dir):
            continue
        candidates.append((fn, path))

    for fn, path in candidates:
        module_file = getattr(sys.modules.get(getattr(fn, "__module__", "")), "__file__", "") or ""
        if module_file and os.path.basename(module_file) == os.path.basename(path):
            return fn
    return candidates[0][0] if candidates else None


def _source_file(view: Any) -> str:
    """Basename of the file the endpoint's own function lives in."""
    import os

    fn = _original_function(view)
    if fn is not None:
        return os.path.basename(fn.__code__.co_filename)

    # bound methods, class-based views, callables without __code__
    try:
        fallback = inspect.getsourcefile(getattr(view, "view_class", None) or view) or ""
    except (TypeError, OSError):
        fallback = ""
    return os.path.basename(fallback) if fallback else ""


# flask_parameter_validation marks where each argument comes from on the
# argument's default value: ``Query(...)``, ``Json(...)``, ``Form(...)``,
# ``Route(...)``, ``File(...)``. Each class carries a ``name`` naming its source.
# Detected by shape (module + ``name``), so the package is never imported.
_VALIDATOR_LOCATIONS = {"query": "query", "json": "body", "form": "form", "route": "path", "file": "body"}


# A validator's regex often says exactly what a valid value looks like; the
# common shapes get a matching example (anything else falls back to the name/type guess).
_PATTERN_EXAMPLES = {
    r"\d{4}-\d{2}-\d{2}": "2026-01-15",
    r"^\d{4}-\d{2}-\d{2}$": "2026-01-15",
}


def _constraint_text(marker: Any) -> str:
    """A short human description of a validator's limits (length, range, pattern)."""
    bits = []
    low, high = getattr(marker, "min_str_length", None), getattr(marker, "max_str_length", None)
    if low is not None and high is not None:
        bits.append(f"{low}-{high} characters")
    elif low is not None:
        bits.append(f"at least {low} characters")
    elif high is not None:
        bits.append(f"at most {high} characters")
    low, high = getattr(marker, "min_int", None), getattr(marker, "max_int", None)
    if low is not None and high is not None:
        bits.append(f"between {low} and {high}")
    elif low is not None:
        bits.append(f"minimum {low}")
    elif high is not None:
        bits.append(f"maximum {high}")
    if getattr(marker, "pattern", None):
        bits.append(f"pattern {marker.pattern}")
    return ", ".join(bits)


def _validator_params(view: Any) -> List["ParamSpec"]:
    """Parameters declared as ``name: type = Query(...) / Json(...) / Route(...)``
    on the endpoint's signature. The signature lives on the original function,
    which the validator decorator wraps, so look through the wrappers."""
    for fn in _reachable_functions(view):
        try:
            signature = inspect.signature(fn)
        except (TypeError, ValueError):
            continue
        try:
            hints = typing.get_type_hints(fn, include_extras=True)  # resolves string annotations
        except Exception:
            hints = {}
        specs: List[ParamSpec] = []
        for param in signature.parameters.values():
            marker = param.default
            source = getattr(type(marker), "name", None)
            if not str(type(marker).__module__).startswith("flask_parameter_validation") or source not in _VALIDATOR_LOCATIONS:
                continue
            annotation = hints.get(param.name, param.annotation)
            args = getattr(annotation, "__args__", ())
            optional = type(None) in args  # Optional[X] / Union[X, None]
            inner = [a for a in args if a is not type(None)]  # noqa: E721
            base = inner[0] if optional and len(inner) == 1 else annotation
            default = getattr(marker, "default", None)
            location = _VALIDATOR_LOCATIONS[source]
            type_name = "file" if source == "file" else _annotation_name(base)
            specs.append(
                ParamSpec(
                    name=param.name,
                    location=location,
                    type=type_name,
                    required=location == "path" or (not optional and default is None),
                    default=_safe(default) if default is not None else None,
                    description=_constraint_text(marker),
                    example=_PATTERN_EXAMPLES.get(getattr(marker, "pattern", None)),
                )
            )
        if specs:
            return specs
    return []


def _flask_request_params(view: Any) -> List["ParamSpec"]:
    """Parameters read straight off Flask's ``request`` in the view's source:
    ``request.args.get("x")``, ``request.get_json()["x"]``, ``request.form[...]``,
    ``request.files["f"]``. Flask views declare none of this in a signature."""
    import ast
    import textwrap

    fn = _original_function(view)
    if fn is None:
        return []
    try:
        tree = ast.parse(textwrap.dedent(inspect.getsource(fn)))
    except (OSError, TypeError, SyntaxError, IndentationError):
        return []
    func = next((n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))), None)
    if func is None:
        return []

    def is_request(node: Any) -> bool:
        return isinstance(node, ast.Name) and node.id == "request"

    def source_kind(node: Any) -> str:
        if isinstance(node, ast.Attribute) and is_request(node.value):
            return {"args": "query", "values": "query", "form": "form", "json": "body", "data": "body", "files": "files"}.get(node.attr, "")
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and is_request(node.func.value) and node.func.attr in ("get_json", "get_data")):
            return "body"
        return ""

    variables: Dict[str, str] = {}
    for node in ast.walk(func):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            kind = source_kind(node.value)
            if kind:
                variables[node.targets[0].id] = kind

    def kind_of(node: Any) -> str:
        return variables.get(node.id, "") if isinstance(node, ast.Name) else source_kind(node)

    found: Dict[tuple, ParamSpec] = {}

    def record(kind: str, name: str, required: bool, default: Any = None, type_name: str = "string") -> None:
        location = {"query": "query", "form": "form"}.get(kind, "body")
        if kind == "files":
            type_name = "file"
        key = (location, name)
        if key in found:
            found[key].required = found[key].required or required
            return
        found[key] = ParamSpec(
            name=name, location=location, type=type_name, required=required,
            default=default if isinstance(default, (str, int, float, bool)) else None,
        )

    for node in ast.walk(func):
        if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
            kind = kind_of(node.value)
            if kind and isinstance(node.ctx, ast.Load):
                record(kind, node.slice.value, True)
        elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in ("get", "getlist")
              and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)):
            kind = kind_of(node.func.value)
            if not kind:
                continue
            default = node.args[1].value if len(node.args) > 1 and isinstance(node.args[1], ast.Constant) else None
            type_name = "string"
            for keyword in node.keywords:
                if keyword.arg == "default" and isinstance(keyword.value, ast.Constant):
                    default = keyword.value.value
                elif keyword.arg == "type" and isinstance(keyword.value, ast.Name):
                    type_name = {"int": "int", "float": "float", "bool": "bool", "str": "string"}.get(keyword.value.id, type_name)
            record(kind, node.args[0].value, False, default, type_name)
    return list(found.values())


def _merge_flask_params(path_params: List["ParamSpec"], view: Any, method: str) -> List["ParamSpec"]:
    """Path parameters from the URL rule, plus what the view itself declares it
    reads (validator markers, then direct ``request`` use). A body needs a
    method that carries one, so GET/HEAD keep query parameters only."""
    if view is None:
        return path_params
    params = list(path_params)
    has_body = method.upper() in ("POST", "PUT", "PATCH", "DELETE")

    for spec in _validator_params(view):
        if spec.location == "path":
            # Already known from the URL; the declaration adds the real type and limits.
            existing = next((p for p in params if p.name == spec.name and p.location == "path"), None)
            if existing is not None:
                if existing.type == "string" and spec.type not in ("string", "str", "any"):
                    existing.type = spec.type
                existing.description = existing.description or spec.description
            continue
        if spec.location != "query" and not has_body:
            continue
        params.append(spec)

    seen = {p.name for p in params}
    for spec in _flask_request_params(view):
        if spec.name in seen or (spec.location != "query" and not has_body):
            continue
        params.append(spec)
        seen.add(spec.name)
    return params


def _reachable_functions(view: Any, limit: int = 40) -> List[Any]:
    """``view`` plus every function it wraps. Follows ``__wrapped__`` and also
    closure cells, because some decorators (e.g. Flask-Parameter-Validation's
    ``@ValidateParameters``) wrap without setting ``__wrapped__``, which would
    otherwise hide the original function and the decorators written on it."""
    import types

    found: List[Any] = []
    seen: set = set()
    stack = [view]
    while stack and len(found) < limit:
        fn = stack.pop()
        if id(fn) in seen or not isinstance(fn, types.FunctionType):
            continue
        seen.add(id(fn))
        found.append(fn)
        wrapped = getattr(fn, "__wrapped__", None)
        if wrapped is not None:
            stack.append(wrapped)
        for cell in fn.__closure__ or ():
            try:
                stack.append(cell.cell_contents)
            except ValueError:  # empty cell
                pass
    return found


def _has_auth_decorator(view: Any) -> bool:
    """Read the decorators written above a view's own ``def`` — a name-only
    check can't see them, since decorators like ``@authorize.in_group("admin")``
    wrap the view under its original name."""
    import ast
    import textwrap

    for fn in _reachable_functions(view):
        try:
            tree = ast.parse(textwrap.dedent(inspect.getsource(fn)))
        except (OSError, TypeError, SyntaxError, IndentationError):
            continue
        func = next((n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))), None)
        if func is None:
            continue
        for dec in func.decorator_list:
            target = dec.func if isinstance(dec, ast.Call) else dec
            parts = []
            while isinstance(target, ast.Attribute):
                parts.append(target.attr)
                target = target.value
            if isinstance(target, ast.Name):
                parts.append(target.id)
            dotted = ".".join(reversed(parts)).lower()
            if "csrf" in dotted:
                continue
            if any(hint in dotted for hint in _AUTH_DECORATOR_HINTS):
                return True
    return False


def _unwrap_annotation(annotation: Any) -> Any:
    """``Optional[X]`` / ``X | None`` / ``Annotated[X, ...]`` -> ``X``."""
    for _ in range(4):
        args = getattr(annotation, "__args__", ())
        if getattr(annotation, "__metadata__", None) is not None and args:
            annotation = args[0]
            continue
        real = [a for a in args if a is not type(None)]  # noqa: E721
        if real and (getattr(annotation, "__origin__", None) is Union or type(annotation).__name__ == "UnionType"):
            annotation = real[0]
            continue
        break
    return annotation


_CONSTRAINT_NAMES = (
    "pattern", "min_length", "max_length", "ge", "gt", "le", "lt", "multiple_of",
)


def _field_facts(info: Any, annotation: Any) -> Tuple[List[Any], Dict[str, Any], Any]:
    """``(choices, constraints, example)`` a FastAPI/Pydantic field declares:
    Literal/Enum values, validation rules, and one value that satisfies them
    (``Form(pattern="^password$")`` -> ``"password"``)."""
    import enum
    import re as _re
    import typing

    annotation = _unwrap_annotation(annotation)
    choices: List[Any] = []
    if typing.get_origin(annotation) is typing.Literal:
        choices = [_safe(v) for v in typing.get_args(annotation)]
    elif isinstance(annotation, type) and issubclass(annotation, enum.Enum):
        choices = [_safe(m.value) for m in annotation]

    constraints: Dict[str, Any] = {}
    for meta in getattr(info, "metadata", None) or []:
        for name in _CONSTRAINT_NAMES:
            value = getattr(meta, name, None)
            if value is not None:
                constraints[name] = _safe(value)

    example: Any = None
    pattern = constraints.get("pattern")
    if isinstance(pattern, str):
        literal = _re.fullmatch(r"\^?([A-Za-z0-9_.\-]+)\$?", pattern)
        if literal:
            example = literal.group(1)
    if example is None and not choices:
        kind = getattr(annotation, "__name__", "")
        if kind in ("int", "float"):
            cast = int if kind == "int" else float
            if "ge" in constraints:
                example = cast(constraints["ge"])
            elif "gt" in constraints:
                example = cast(constraints["gt"]) + (1 if kind == "int" else 0.5)
            elif "le" in constraints:
                example = cast(constraints["le"])
            elif "lt" in constraints:
                example = cast(constraints["lt"]) - (1 if kind == "int" else 0.5)
    return choices, constraints, example


def _field_description(info: Any) -> str:
    """The field's description: ``Field(description=...)`` if set, otherwise the
    first sentence of the ``Doc(...)`` annotation FastAPI attaches to its own
    fields (``OAuth2PasswordRequestForm``'s ``scope``, ``client_id``...)."""
    text = str(getattr(info, "description", None) or "").strip()
    if text:
        return " ".join(text.split())
    for meta in getattr(info, "metadata", None) or []:
        doc = getattr(meta, "documentation", None)
        if isinstance(doc, str) and doc.strip():
            text = " ".join(doc.split())
            # Whole sentences, until it says something (a bare "`username` string."
            # is not enough) and before it turns into a paragraph.
            sentences = [part.strip() for part in re.split(r"(?<=[.!?])\s+", text) if part.strip()]
            out = ""
            for sentence in sentences:
                if out and len(out) + len(sentence) > 200:
                    break
                out = f"{out} {sentence}".strip()
                if len(out) >= 40:
                    break
            return out if len(out) <= 200 else out[:197].rstrip() + "..."
    return ""


def _field_location(info: Any, default_location: str) -> str:
    kind = type(info).__name__
    if kind == "Form":
        return "form"
    if kind == "File":
        return "body"
    return default_location


def _spec_from_field(field: Any, location: str) -> Optional[ParamSpec]:
    """One ParamSpec from a FastAPI-resolved field (``dependant.*_params``)."""
    info = getattr(field, "field_info", None)
    name = getattr(info, "alias", None) or getattr(field, "name", None)
    if not name:
        return None
    annotation = _unwrap_annotation(getattr(info, "annotation", None))
    kind = type(info).__name__
    try:
        required = bool(info.is_required())
    except Exception:
        required = bool(getattr(field, "required", True))
    default = None if required else getattr(info, "default", None)
    if type(default).__name__ == "PydanticUndefinedType":
        default = None
    choices, constraints, example = _field_facts(info, getattr(info, "annotation", None))
    return ParamSpec(
        name=name,
        location=_field_location(info, location),
        type="file" if kind == "File" else _annotation_name(annotation),
        required=required,
        default=_safe(default),
        description=_field_description(info),
        example=example,
        choices=choices,
        constraints=constraints,
    )


def _fastapi_dependency_params(route: Any, skip: set) -> List[ParamSpec]:
    """Caller-supplied inputs declared by ``Depends(...)`` sub-dependencies.

    ``_fastapi_signature_params`` rightly skips ``x = Depends(...)`` as
    injected, but a dependency can itself declare request inputs -- the
    standard case is ``form: OAuth2PasswordRequestForm = Depends()``, whose
    ``username``/``password`` fields the caller must send. FastAPI has already
    resolved these into ``route.dependant``; read them from there. Additive and
    best-effort: a FastAPI version difference returns what was found so far
    instead of breaking discovery.
    """
    out: List[ParamSpec] = []
    seen = set(skip)
    root = getattr(route, "dependant", None)
    if root is None:
        return out

    def add(field: Any, location: str) -> None:
        spec = _spec_from_field(field, location)
        if spec is not None and spec.name not in seen:
            seen.add(spec.name)
            out.append(spec)

    def walk(dependant: Any, depth: int = 0, visited: Optional[set] = None) -> None:
        visited = visited if visited is not None else set()
        if depth > 8:
            return
        for sub in getattr(dependant, "dependencies", None) or []:
            if id(sub) in visited:
                continue
            visited.add(id(sub))
            for field in getattr(sub, "path_params", None) or []:
                add(field, "path")
            for field in getattr(sub, "query_params", None) or []:
                add(field, "query")
            for field in getattr(sub, "body_params", None) or []:
                add(field, "body")
            walk(sub, depth + 1, visited)

    try:
        walk(root)
    except Exception:
        pass
    return out


def _fastapi_refine_own_params(params: List[ParamSpec], route: Any) -> None:
    """Correct the endpoint's own parameters with what FastAPI resolved.

    The signature pass is a heuristic (``str = Form()`` looks like a query
    parameter; ``Annotated[int, Query(ge=1)]`` loses its rule). For every
    parameter FastAPI also lists in ``route.dependant`` -- matched by name --
    take its location (form vs query vs body), required/optional, default,
    description, allowed values and constraints from FastAPI itself."""
    root = getattr(route, "dependant", None)
    if root is None:
        return
    by_name = {p.name: p for p in params}
    try:
        groups = (
            ("path", getattr(root, "path_params", None) or []),
            ("query", getattr(root, "query_params", None) or []),
            ("body", getattr(root, "body_params", None) or []),
        )
        for location, fields in groups:
            for field in fields:
                spec = _spec_from_field(field, location)
                if spec is None:
                    continue
                current = by_name.get(spec.name)
                if current is None:
                    if location in ("path", "query"):  # a body field named after a model arg is expanded elsewhere
                        params.append(spec)
                        by_name[spec.name] = spec
                    continue
                if location == "body" and spec.location not in ("form", "body"):
                    continue
                if current.location != "path":
                    current.location = spec.location
                current.required = spec.required
                current.default = spec.default
                if spec.description:
                    current.description = spec.description
                if spec.choices:
                    current.choices = spec.choices
                if spec.constraints:
                    current.constraints = spec.constraints
                if spec.example is not None and current.example is None:
                    current.example = spec.example
    except Exception:
        pass


_SECURITY_SCHEME_NAMES = {
    "HTTPBearer": "bearer", "OAuth2PasswordBearer": "bearer",
    "OAuth2AuthorizationCodeBearer": "bearer", "OAuth2": "bearer",
    "OpenIdConnect": "bearer", "HTTPBasic": "basic", "HTTPDigest": "digest",
}
_AUTH_DEPENDENCY_WORDS = {
    "auth", "authenticate", "authenticated", "authorize", "authorized", "token",
    "permission", "permissions", "require", "required", "requires", "verify",
    "admin", "jwt", "apikey",
}


def _fastapi_auth_info(route: Any) -> Optional[Tuple[bool, bool, str]]:
    """``(requires_auth, auth_optional, scheme)`` from FastAPI's own resolved
    dependency tree, or ``None`` when it cannot be read.

    A security scheme (``OAuth2PasswordBearer``, ``HTTPBearer``, ``APIKeyHeader``
    ...) found anywhere in the chain -- directly or behind ``get_current_user``
    -- means the endpoint needs a token; ``auto_error=False`` schemes accept a
    token without requiring one. A dependency with no scheme that is named like
    an auth guard is a fallback, and a route with neither needs no token."""
    root = getattr(route, "dependant", None)
    if root is None:
        return None
    try:
        from fastapi.security.base import SecurityBase  # type: ignore
    except Exception:
        SecurityBase = None  # noqa: N806

    schemes: List[Tuple[str, bool]] = []
    guards: List[Tuple[str, bool]] = []
    visited: set = set()

    def scheme_of(call: Any) -> str:
        cls = type(call).__name__
        if cls in _SECURITY_SCHEME_NAMES:
            return _SECURITY_SCHEME_NAMES[cls]
        if cls.startswith("APIKey"):
            model = getattr(call, "model", None)
            return f"apikey:{getattr(model, 'name', '') or cls}"
        return cls.lower()

    def walk(dependant: Any, depth: int = 0) -> None:
        if depth > 12:
            return
        for sub in getattr(dependant, "dependencies", None) or []:
            if id(sub) in visited:
                continue
            visited.add(id(sub))
            call = getattr(sub, "call", None)
            if SecurityBase is not None and isinstance(call, SecurityBase):
                schemes.append((scheme_of(call), bool(getattr(call, "auto_error", True))))
            else:
                # Only plain functions can be auth guards without a security
                # scheme; a class dependency (OAuth2PasswordRequestForm, a
                # pagination model...) is request input, never a guard.
                name = (getattr(call, "__name__", "") or "").lower() if inspect.isroutine(call) else ""
                words = set(name.split("_"))
                if name and (words & _AUTH_DEPENDENCY_WORDS or {"current", "user"} <= words or {"current", "admin"} <= words):
                    guards.append((name, "optional" not in words))
            for header in getattr(sub, "header_params", None) or []:
                if (getattr(header, "alias", None) or getattr(header, "name", "")).lower() == "authorization":
                    schemes.append(("bearer", True))
            walk(sub, depth + 1)

    try:
        walk(root)
    except Exception:
        return None
    if schemes:
        required = [s for s in schemes if s[1]]
        scheme = (required or schemes)[0][0]
        return bool(required), not required, scheme
    if guards:
        required = [g for g in guards if g[1]]
        return bool(required), not required, "bearer"
    return False, False, ""


def _fastapi_signature_params(endpoint: Any, skip: set) -> List[ParamSpec]:
    params: List[ParamSpec] = []
    try:
        signature = inspect.signature(endpoint)
    except (TypeError, ValueError):
        return params
    # `from __future__ import annotations` in the monitored app's module
    # makes every annotation a plain string at runtime; get_type_hints()
    # resolves it back to the real class so Pydantic models are still
    # detected. Falls back to the raw annotation if resolution fails.
    try:
        resolved_hints = typing.get_type_hints(endpoint, include_extras=True)
    except Exception:
        resolved_hints = {}
    for param in signature.parameters.values():
        if param.name in skip or param.name in {"request", "response", "background_tasks"}:
            continue
        if _is_fastapi_dependency(param.default):
            continue  # injected (db session, current-user guard...), not caller input
        raw_annotation = resolved_hints.get(param.name, param.annotation)
        annotation = _annotation_name(raw_annotation)
        if annotation in {"Request", "Response", "BackgroundTasks"}:
            continue
        if annotation in {"UploadFile", "list[UploadFile]"}:
            params.append(
                ParamSpec(
                    name=param.name, location="body", type="file",
                    required=param.default is inspect.Parameter.empty,
                )
            )
            continue
        if annotation in {"int", "str", "float", "bool", "any"}:
            location = "query"
        else:
            location = "body"
            actual = raw_annotation
            args = [a for a in getattr(raw_annotation, "__args__", ()) if a is not type(None)]  # noqa: E721
            if args and getattr(raw_annotation, "__origin__", None) is Union:
                actual = args[0]
            if _is_pydantic_model(actual):
                expanded = _expand_pydantic_params(actual, location)
                if expanded is not None:
                    params.extend(expanded)
                    continue
        default = param.default
        required = default is inspect.Parameter.empty
        # Body(...)/Query(...)/etc. wrap the real default in a FieldInfo;
        # `...` (or Pydantic's "undefined" sentinel) inside means required.
        if not required and type(default).__module__.startswith(("fastapi", "pydantic")) and hasattr(default, "default"):
            inner = default.default
            if inner is Ellipsis or type(inner).__name__ == "PydanticUndefinedType":
                required, default = True, inspect.Parameter.empty
            else:
                default = inner
        params.append(
            ParamSpec(
                name=param.name,
                location=location,
                type=annotation,
                required=required,
                default=None if default is inspect.Parameter.empty else _safe(default),
            )
        )
    return params
