# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Flask integration.

``bl.install(app)`` does three things:

1. opens a capture context for every request (``before_request``),
2. records the exception through the ``got_request_exception`` signal, so the
   application's own error handling is left untouched,
3. mounts the dashboard blueprint at the configured path.
"""

from __future__ import annotations

from typing import Any, Optional

from ..models import KIND_HTTP


def install_flask(app: Any, jscoup: Any, mount_path: str = "/__jscoup", **kwargs: Any) -> Any:
    from flask import Blueprint, Response as FlaskResponse, g, got_request_exception, request

    config = jscoup.config

    @app.before_request
    def _jscoup_before():
        if request.path.startswith(mount_path):
            return None
        token, source, scheme = jscoup.identity.extract(
            headers=dict(request.headers), query=request.args, cookies=request.cookies
        )
        route = request.url_rule.rule if request.url_rule else request.path
        ctx = jscoup.begin(
            kind=KIND_HTTP,
            name=f"{request.method} {route}",
            method=request.method,
            path=request.path,
            route=route,
            query_string=request.query_string.decode("utf-8", "replace"),
            client_ip=(request.headers.get("X-Forwarded-For") if config.trust_proxy_headers else None)
            or request.remote_addr,
            actor=jscoup.identity.resolve(token, source, scheme),
            simulation_id=request.headers.get("X-JSCoup-Simulation"),
            trace_id=request.headers.get("X-Request-Id") or request.headers.get("X-Trace-Id"),
        )
        if config.capture_headers:
            ctx.headers = jscoup.redactor.scrub_headers(request.headers)
        ctx.params = _collect_params(request, jscoup)
        ctx.body_preview = _body_preview(request, jscoup)
        g._jscoup_ctx = ctx
        g._jscoup_done = False
        return None

    @app.after_request
    def _jscoup_after(response):
        ctx = getattr(g, "_jscoup_ctx", None)
        if ctx is not None:
            ctx.status_code = response.status_code
            if response.content_type and "json" in response.content_type:
                try:
                    ctx.response_preview = jscoup.redactor.scrub_text(
                        response.get_data(as_text=True), config.body_preview_chars
                    )
                except RuntimeError:  # streamed response
                    pass
        return response

    @app.teardown_request
    def _jscoup_teardown(exc):
        ctx = getattr(g, "_jscoup_ctx", None)
        if ctx is None:
            return
        if getattr(g, "_jscoup_done", False):
            from ..context import pop

            pop(ctx)
        else:
            jscoup.end(ctx, exception=exc)
        g._jscoup_ctx = None

    def _on_exception(sender, exception, **extra):
        ctx = getattr(g, "_jscoup_ctx", None)
        if ctx is None:
            jscoup.record_exception(exception, name=request.path, kind=KIND_HTTP)
            return
        ctx.status_code = ctx.status_code or 500
        jscoup.finish(ctx, exception=exception)
        g._jscoup_done = True

    got_request_exception.connect(_on_exception, app)

    # ---- dashboard -------------------------------------------------------- #
    if config.dashboard_enabled and config.dashboard_mount_in_app:
        blueprint = Blueprint("jscoup", __name__)

        @blueprint.route("/", defaults={"subpath": ""}, methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
        @blueprint.route("/<path:subpath>", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
        def _dashboard(subpath: str):
            limit = config.dashboard_max_body_bytes
            if request.content_length is not None and request.content_length > limit:
                return FlaskResponse('{"error":"Request body too large"}', status=413, content_type="application/json")
            body = request.stream.read(limit + 1)
            if len(body) > limit:
                return FlaskResponse('{"error":"Request body too large"}', status=413, content_type="application/json")
            result = jscoup.dashboard.handle(
                path="/" + subpath,
                method=request.method,
                query=request.args.to_dict(),
                body=body,
                headers=dict(request.headers),
                base_url=request.host_url.rstrip("/"),
                client_ip=(request.headers.get("X-Forwarded-For") if config.trust_proxy_headers else None)
                or request.remote_addr,
            )
            return FlaskResponse(result.body, status=result.status, headers=result.all_headers())

        app.register_blueprint(blueprint, url_prefix=mount_path)

    jscoup.registry.discover_flask(app, mount_path)
    jscoup._route_source = {"framework": "flask", "app": app, "mount": mount_path}
    app.extensions["jscoup"] = jscoup
    return app


def _collect_params(request: Any, jscoup: Any) -> dict:
    params = {}
    if request.view_args:
        params.update(request.view_args)
    if request.args:
        params.update(request.args.to_dict(flat=True))
    if request.form:
        params.update(request.form.to_dict(flat=True))
    if request.is_json:
        payload = request.get_json(silent=True)
        if isinstance(payload, dict):
            params.update(payload)
        elif payload is not None:
            params["__body__"] = payload
    return jscoup.redactor.scrub(params)


def _body_preview(request: Any, jscoup: Any) -> Optional[str]:
    try:
        raw = request.get_data(cache=True, as_text=True)
    except Exception:
        return None
    if not raw:
        return None
    return jscoup.redactor.scrub_body(raw, jscoup.config.body_preview_chars)
