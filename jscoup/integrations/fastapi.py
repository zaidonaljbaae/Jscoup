# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""FastAPI / Starlette integration.

A pure ASGI middleware is used (not ``BaseHTTPMiddleware``) so streaming
responses, background tasks and exception propagation behave exactly as they do
without JSCoup.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional
from urllib.parse import parse_qsl

from ..models import KIND_HTTP


class JSCoupASGIMiddleware:
    """Capture every HTTP request handled by an ASGI application."""

    def __init__(self, app: Any, jscoup: Any, mount_path: str = "/__jscoup"):
        self.app = app
        self.jscoup = jscoup
        self.mount_path = mount_path

    async def __call__(self, scope: Dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http" or scope.get("path", "").startswith(self.mount_path):
            await self.app(scope, receive, send)
            return

        jscoup = self.jscoup
        config = jscoup.config
        headers = {
            k.decode("latin-1"): v.decode("latin-1") for k, v in scope.get("headers", [])
        }
        query = dict(parse_qsl(scope.get("query_string", b"").decode("latin-1")))
        cookies = _parse_cookies(headers.get("cookie", ""))
        token, source, scheme = jscoup.identity.extract(headers=headers, query=query, cookies=cookies)

        route = _route_of(scope)
        ctx = jscoup.begin(
            kind=KIND_HTTP,
            name=f"{scope.get('method')} {route or scope.get('path')}",
            method=scope.get("method"),
            path=scope.get("path"),
            route=route,
            query_string=scope.get("query_string", b"").decode("latin-1"),
            client_ip=(scope.get("client") or ["", ""])[0],
            actor=jscoup.identity.resolve(token, source, scheme),
            simulation_id=headers.get("x-jscoup-simulation"),
            trace_id=headers.get("x-request-id") or headers.get("x-trace-id"),
        )
        if config.capture_headers:
            ctx.headers = jscoup.redactor.scrub_headers(headers)
        ctx.params = dict(query)

        body_chunks: list = []

        async def receive_wrapper():
            message = await receive()
            if message.get("type") == "http.request":
                chunk = message.get("body", b"")
                if chunk and sum(len(c) for c in body_chunks) < config.body_preview_chars * 2:
                    body_chunks.append(chunk[:max(0, config.body_preview_chars * 2 - sum(map(len, body_chunks)))])
            return message

        response_chunks: list = []
        response_is_json = False

        async def send_wrapper(message):
            nonlocal response_is_json
            if message.get("type") == "http.response.body":
                # A bounded copy of a JSON response body, so the call log can
                # show what every call returned (and offer real examples).
                chunk = message.get("body", b"")
                if response_is_json and chunk and sum(len(c) for c in response_chunks) < config.body_preview_chars * 2:
                    response_chunks.append(chunk[:max(0, config.body_preview_chars * 2 - sum(map(len, response_chunks)))])
            if message.get("type") == "http.response.start":
                response_is_json = any(
                    k.lower() == b"content-type" and b"json" in v.lower() for k, v in message.get("headers", [])
                )
                ctx.status_code = message.get("status")
                # the router resolves the endpoint after the middleware runs
                resolved = _route_of(scope)
                if resolved:
                    ctx.route = resolved
                    ctx.name = f"{scope.get('method')} {resolved}"
                path_params = scope.get("path_params") or {}
                if path_params:
                    ctx.params.update(path_params)
            await send(message)

        try:
            await self.app(scope, receive_wrapper, send_wrapper)
        except BaseException as exc:  # noqa: BLE001 - re-raised after capture
            # asyncio.CancelledError is a BaseException, not an Exception,
            # and a client disconnect or server-side timeout cancels the
            # task running this request fairly routinely, so it must be
            # caught here too.
            _attach_body(ctx, body_chunks, jscoup)
            resolved = _route_of(scope)
            if resolved:
                ctx.route = resolved
                ctx.name = f"{scope.get('method')} {resolved}"
            ctx.params.update(scope.get("path_params") or {})
            ctx.status_code = ctx.status_code or 500
            jscoup.end(ctx, exception=exc)
            raise
        else:
            _attach_body(ctx, body_chunks, jscoup)
            if response_chunks:
                ctx.response_preview = jscoup.redactor.scrub_body(
                    b"".join(response_chunks).decode("utf-8", "replace"), config.body_preview_chars
                )
            jscoup.end(ctx)


def install_fastapi(app: Any, jscoup: Any, mount_path: str = "/__jscoup", **kwargs: Any) -> Any:
    from fastapi import APIRouter, Request
    from fastapi.responses import Response as FastAPIResponse

    if jscoup.config.dashboard_enabled and jscoup.config.dashboard_mount_in_app:
        router = APIRouter()

        async def _dashboard(request, subpath=""):
            from starlette.concurrency import run_in_threadpool

            limit = jscoup.config.dashboard_max_body_bytes
            chunks = bytearray()
            async for chunk in request.stream():
                if len(chunks) + len(chunk) > limit:
                    return FastAPIResponse(content=b'{"error":"Request body too large"}', status_code=413, media_type="application/json")
                chunks.extend(chunk)
            body = bytes(chunks)
            # Off the event loop: dashboard.handle() is a plain sync call,
            # and when the gateway is enabled it can make its own blocking
            # HTTP loopback call back into this same app, which would
            # deadlock a single worker if run inline.
            result = await run_in_threadpool(
                jscoup.dashboard.handle,
                path="/" + subpath,
                method=request.method,
                query=dict(request.query_params),
                body=body,
                headers=dict(request.headers),
                base_url=str(request.base_url).rstrip("/"),
                client_ip=(request.headers.get("x-forwarded-for") if jscoup.config.trust_proxy_headers else None)
                or (request.client.host if request.client else None),
            )
            return FastAPIResponse(
                content=result.body,
                status_code=result.status,
                media_type=result.content_type,
                headers={k: v for k, v in result.all_headers().items() if k != "Content-Type"},
            )

        # This module uses ``from __future__ import annotations``; FastAPI resolves
        # annotations at import time, so they are attached as real objects here.
        _dashboard.__annotations__ = {"request": Request, "subpath": str}

        router.add_api_route(
            mount_path, _dashboard, methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"], include_in_schema=False
        )
        router.add_api_route(
            mount_path + "/{subpath:path}", _dashboard, methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
            include_in_schema=False,
        )
        app.include_router(router)

    app.add_middleware(JSCoupASGIMiddleware, jscoup=jscoup, mount_path=mount_path)
    jscoup.registry.discover_fastapi(app, mount_path)
    jscoup._route_source = {"framework": "fastapi", "app": app, "mount": mount_path}
    setattr(app.state, "jscoup", jscoup) if hasattr(app, "state") else None
    return app


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #


def _route_of(scope: Dict[str, Any]) -> Optional[str]:
    route = scope.get("route")
    return getattr(route, "path", None) if route is not None else None


def _parse_cookies(header: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for part in (header or "").split(";"):
        if "=" in part:
            key, value = part.split("=", 1)
            out[key.strip()] = value.strip()
    return out


def _attach_body(ctx: Any, chunks: list, jscoup: Any) -> None:
    if not chunks:
        return
    raw = b"".join(chunks).decode("utf-8", "replace")
    ctx.body_preview = jscoup.redactor.scrub_body(raw, jscoup.config.body_preview_chars)
    try:
        payload = json.loads(raw)
        if isinstance(payload, dict):
            ctx.params.update(jscoup.redactor.scrub(payload))
    except (json.JSONDecodeError, ValueError):
        pass
