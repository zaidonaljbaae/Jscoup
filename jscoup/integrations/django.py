# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Django integration.

Two pieces:

``JSCoupMiddleware``
    Add ``"jscoup.integrations.django.JSCoupMiddleware"`` to ``MIDDLEWARE``.
    It reads the active instance from ``settings.JSCOUP`` or from the module
    level default registered by :func:`install_django`.

``urlpatterns``
    ``urlpatterns += jscoup_urls(bl)`` mounts the dashboard.
"""

from __future__ import annotations

from typing import Any, List, Optional

from ..models import KIND_HTTP

_default_instance: Optional[Any] = None


def install_django(jscoup: Any, mount_path: str = "/__jscoup", **kwargs: Any) -> Any:
    """Register the instance so the middleware and URLs can find it."""
    global _default_instance
    _default_instance = jscoup
    jscoup.config.mount_path = mount_path
    jscoup._route_source = {"framework": "django", "mount": mount_path}
    try:
        from ..dbwatch import instrument_django

        instrument_django()
    except Exception:  # Django not fully configured yet — the middleware retries
        pass
    return jscoup


def get_instance() -> Optional[Any]:
    global _default_instance
    if _default_instance is not None:
        return _default_instance
    try:
        from django.conf import settings  # type: ignore

        return getattr(settings, "JSCOUP", None)
    except Exception:
        return None


class JSCoupMiddleware:
    """Django middleware that captures requests and unhandled exceptions."""

    def __init__(self, get_response):
        self.get_response = get_response
        self.jscoup = get_instance()
        if self.jscoup is not None:
            try:
                from ..dbwatch import instrument_django

                instrument_django()
            except Exception:
                pass
            try:
                self.jscoup.registry.discover_django(self.jscoup.config.mount_path)
            except Exception:
                pass

    def __call__(self, request):
        jscoup = self.jscoup or get_instance()
        if jscoup is None or request.path.startswith(jscoup.config.mount_path):
            return self.get_response(request)

        # Connections are thread-local; install in the actual ORM execution thread.
        from ..dbwatch import instrument_django
        instrument_django()
        headers = {k: v for k, v in request.headers.items()}
        token, source, scheme = jscoup.identity.extract(
            headers=headers, query=request.GET, cookies=request.COOKIES
        )
        ctx = jscoup.begin(
            kind=KIND_HTTP,
            name=f"{request.method} {request.path}",
            method=request.method,
            path=request.path,
            route=getattr(getattr(request, "resolver_match", None), "route", request.path),
            query_string=request.META.get("QUERY_STRING", ""),
            client_ip=request.META.get("REMOTE_ADDR"),
            actor=jscoup.identity.resolve(token, source, scheme),
            simulation_id=request.headers.get("X-JSCoup-Simulation"),
        )
        if jscoup.config.capture_headers:
            ctx.headers = jscoup.redactor.scrub_headers(headers)
        ctx.params = jscoup.redactor.scrub(_params(request))
        request._jscoup_ctx = ctx
        request._jscoup_done = False

        try:
            response = self.get_response(request)
        except Exception as exc:
            ctx.status_code = 500
            jscoup.end(ctx, exception=exc)
            raise
        ctx.status_code = getattr(response, "status_code", None)
        if not getattr(response, "streaming", False) and "json" in (response.get("Content-Type", "") or "").lower():
            try:
                ctx.response_preview = jscoup.redactor.scrub_body(
                    response.content.decode("utf-8", "replace"), jscoup.config.body_preview_chars
                )
            except Exception:
                pass
        match = getattr(request, "resolver_match", None)
        if match is not None:
            ctx.route = getattr(match, "route", ctx.route)
            ctx.name = f"{request.method} /{str(ctx.route).lstrip(chr(47))}"
        if getattr(request, "_jscoup_done", False):
            from ..context import pop

            pop(ctx)
        else:
            jscoup.end(ctx)
        return response

    def process_exception(self, request, exception):
        jscoup = self.jscoup or get_instance()
        ctx = getattr(request, "_jscoup_ctx", None)
        if jscoup is None or ctx is None:
            return None
        match = getattr(request, "resolver_match", None)
        if match is not None:
            ctx.route = getattr(match, "route", ctx.route)
            ctx.name = f"{request.method} /{str(ctx.route).lstrip(chr(47))}"
            ctx.name = f"{request.method} {ctx.route}"
        ctx.status_code = ctx.status_code or 500
        jscoup.finish(ctx, exception=exception)
        request._jscoup_done = True
        return None


def dashboard_view(request, subpath: str = ""):
    """Django view that renders the JSCoup dashboard."""
    from django.http import HttpResponse  # type: ignore

    jscoup = get_instance()
    if jscoup is None:
        return HttpResponse(b'{"error":"JSCoup is not installed"}', status=500,
                            content_type="application/json")
    body = request.read(jscoup.config.dashboard_max_body_bytes + 1)
    if len(body) > jscoup.config.dashboard_max_body_bytes:
        return HttpResponse(b'{"error":"Request body too large"}', status=413, content_type="application/json")
    result = jscoup.dashboard.handle(
        path="/" + subpath,
        method=request.method,
        query=request.GET.dict(),
        body=body,
        headers={k: v for k, v in request.headers.items()},
        base_url=f"{request.scheme}://{request.get_host()}",
        client_ip=(request.headers.get("x-forwarded-for") if jscoup.config.trust_proxy_headers else None)
        or request.META.get("REMOTE_ADDR"),
    )
    response = HttpResponse(result.body, status=result.status, content_type=result.content_type)
    for key, value in result.all_headers().items():
        response[key] = value
    return response


def jscoup_urls(jscoup: Any = None, mount_path: Optional[str] = None) -> List[Any]:
    """Return url patterns to append to the project's ``urlpatterns``."""
    from django.urls import path, re_path  # type: ignore

    if jscoup is not None:
        install_django(jscoup, mount_path or jscoup.config.mount_path)
    prefix = (mount_path or (jscoup.config.mount_path if jscoup else "/__jscoup")).strip("/")
    return [
        path(f"{prefix}/", dashboard_view, name="jscoup-dashboard"),
        re_path(rf"^{prefix}/(?P<subpath>.*)$", dashboard_view, name="jscoup-dashboard-sub"),
    ]


def _params(request: Any) -> dict:
    params = dict(request.GET.dict())
    if request.method in ("POST", "PUT", "PATCH"):
        try:
            if request.content_type == "application/json" and request.body:
                import json

                payload = json.loads(request.body.decode("utf-8"))
                if isinstance(payload, dict):
                    params.update(payload)
            else:
                params.update(request.POST.dict())
        except Exception:
            pass
    return params
