# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""The public entry point: :class:`JSCoup`."""

from __future__ import annotations

import asyncio
import copy
import functools
import inspect
import os
import secrets
import socket
import sys
import time
import traceback
from contextlib import contextmanager
from typing import Any, Callable, Dict, Iterable, List, Optional
from urllib.parse import parse_qsl, urlencode

from .analyzers import AnalysisInput, AnalyzerEngine, BaseAnalyzer
from .config import JSCoupConfig
from .context import CaptureContext, add_breadcrumb, current_context, pop, push
from .dbwatch import emit_query, instrument_sqlalchemy, instrument_sqlite3
from .identity import IdentityResolver
from .models import (
    KIND_AZURE_FUNCTION,
    KIND_HTTP,
    KIND_LAMBDA,
    KIND_OCI_FUNCTION,
    KIND_SERVICE,
    KIND_TASK,
    SEVERITY_ERROR,
    SEVERITY_INFO,
    SEVERITY_WARNING,
    STATUS_ERROR,
    STATUS_OK,
    STATUS_SLOW,
    Actor,
    Breadcrumb,
    Diagnosis,
    EventRecord,
    build_fingerprint,
    normalize_sql,
)
from .redaction import Redactor
from .registry import Registry, Target
from .simulator import Simulator
from .storage import BaseStorage, SQLiteStorage

_PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))

# CancelledError/KeyboardInterrupt/SystemExit are BaseException, not
# Exception, and must always propagate rather than being swallowed.
_NEVER_SWALLOW = (asyncio.CancelledError, KeyboardInterrupt, SystemExit)


class JSCoup:
    """Capture, analyse, store and expose failures of an application.

    Typical use::

        bl = JSCoup(service_name="orders-api", db_path=".jscoup/orders.db")
        bl.install(app)                     # Flask / FastAPI / Django

        @bl.watch(kind="service")
        def settle_orders(day: str): ...

    Everything is optional and replaceable: storage backend, analyzers, identity
    resolution, redaction and the dashboard mount path.
    """

    def __init__(
        self,
        service_name: str = "service",
        config: Optional[JSCoupConfig] = None,
        storage: Optional[BaseStorage] = None,
        analyzers: Optional[Iterable[BaseAnalyzer]] = None,
        *,
        dashboard_password: Optional[str] = None,
        **options: Any,
    ):
        if dashboard_password is not None:
            from .dashboard.auth import hash_password

            options["dashboard_password_hash"] = hash_password(dashboard_password)
        self.config = (config or JSCoupConfig()).merged(service_name=service_name, **options)
        if (
            self.config.dashboard_enabled
            and not self.config.dashboard_username
            and not self.config.dashboard_token
            and not self.config.dashboard_local_dev
        ):
            # No credentials and no explicit local-dev opt-in: default to a
            # generated login rather than leaving the dashboard open.
            self.config.dashboard_username = "admin"
        if self.config.dashboard_username and not self.config.dashboard_password_hash:
            # A username was set but no password — generate one and print it once.
            from .dashboard.auth import hash_password

            generated_password = secrets.token_urlsafe(9)
            self.config.dashboard_password_hash = hash_password(generated_password)
            print(
                f"[jscoup] No dashboard_password set for '{self.config.dashboard_username}' — "
                f"generated one: {generated_password}\n"
                f"[jscoup] Pass dashboard_password=... to JSCoup(...) to set your own instead."
            )
        import hashlib
        import threading
        self._aux_lock = threading.RLock()
        self._initial_password_hash = self.config.dashboard_password_hash
        credential = dashboard_password or self.config.dashboard_password_hash or ""
        self._auth_credential_id = hashlib.pbkdf2_hmac("sha256", credential.encode(), b"jscoup-auth-realm-v1", 260000).hex() if credential else ""
        self.storage: BaseStorage = storage or SQLiteStorage(
            db_path=self.config.db_path,
            max_events=self.config.max_events,
            retention_days=self.config.retention_days,
        )
        if self.config.encryption_key:
            from .crypto import EncryptingStorage

            self.storage = EncryptingStorage(self.storage, self.config.encryption_key)
        self.analyzers = AnalyzerEngine(analyzers)
        self.identity = IdentityResolver(self.config)
        self.redactor = Redactor(self.config.sensitive_keys, self.config.mask)
        from .sanitizer import EventSanitizer
        self._sanitizer = EventSanitizer(self.redactor)
        self.registry = Registry()
        self.simulator = Simulator(self)
        self.host = socket.gethostname()
        self._installed_apps: List[str] = []
        self._dashboard_server: Any = None
        self._route_source: Optional[Dict[str, Any]] = None
        self.project_config: Optional[Any] = None  # set by JSCoup.from_config_file()
        from .publisher import EventPublisher
        self._publisher = EventPublisher(self.storage, self.config.event_queue_size, self.config.on_event) if self.config.async_storage else None
        self._closed = False
        self._storage_failures = 0
        self._before_store_failures = 0  # observable counter — see _store()
        if self.config.async_storage and self.config.call_log_enabled:
            self._call_publisher  # allocate SQLite state at startup, not on the request path
        if self.config.capture_print:
            from .printcapture import install_print_capture

            install_print_capture()

    def flush(self, timeout: float = 5.0) -> bool:
        """Wait for accepted queued events. False means work remains."""
        deadline = time.monotonic() + timeout
        events = self._publisher.flush(timeout) if self._publisher else True
        calls = self._call_writer.flush(max(0, deadline-time.monotonic())) if hasattr(self, "_call_writer") else True
        return events and calls

    def close(self, timeout: float = 5.0) -> bool:
        """Flush background work and close this thread's local connections."""
        self._closed = True
        deadline = time.monotonic() + timeout
        complete = self._publisher.close(timeout) if self._publisher else True
        if hasattr(self, "_call_writer"):
            complete = self._call_writer.close(max(0, deadline-time.monotonic())) and complete
        if complete:
            self.storage.close()
            for name in ("_call_log", "_gateway"):
                store = getattr(self, name, None)
                if store is not None:
                    store.close()
            if hasattr(self, "_dashboard") and hasattr(self._dashboard, "_session_store"):
                self._dashboard._session_store.close()
        return complete

    def metrics(self) -> dict:
        return {"before_store_failures":self._before_store_failures,
                "storage_failures":self._storage_failures,
                "call_log_publisher":self._call_writer.metrics() if hasattr(self, "_call_writer") else None,
                "publisher":self._publisher.metrics() if self._publisher else None}

    def rotate_dashboard_credentials(self, password, credential_epoch):
        """Revoke current sessions; deploy the same password/epoch to all workers.

        Epoch is a required operator-controlled version, not a per-worker random value.
        """
        from .dashboard.auth import hash_password
        import hashlib
        with self._aux_lock:
            self.dashboard._sessions.revoke_all()
            self.config.dashboard_password_hash = hash_password(password)
            self.config.credential_epoch = str(credential_epoch)
            self._initial_password_hash = self.config.dashboard_password_hash
            self._auth_credential_id = hashlib.pbkdf2_hmac("sha256", password.encode(), b"jscoup-auth-realm-v1", 260000).hex()
            self.dashboard._sessions  # rebind the local store immediately

    @classmethod
    def high_volume(cls, service_name="service", **options):
        """Bounded async persistence; sampling is opt-in, never implicit."""
        defaults = dict(async_storage=True, capture_success=False, capture_query_caller=False,
                        max_queries=20, max_breadcrumbs=20, capture_headers=False)
        defaults.update(options)
        return cls(service_name=service_name, **defaults)

    @classmethod
    def auto(
        cls,
        app: Any = None,
        service_name: Optional[str] = None,
        *,
        dashboard_username: Optional[str] = None,
        dashboard_password: Optional[str] = None,
        **kwargs: Any,
    ) -> "JSCoup":
        """Build, instrument and (if ``app`` is given) install in one call.

        ``bl = JSCoup.auto(app)`` is the fastest path to full coverage: it
        traces SQLite and installs into ``app`` (Flask/FastAPI/Django), which
        already captures *every* route with no per-route decorator required.
        Pass ``dashboard_username``/``dashboard_password`` here to enable
        dashboard login in the same call. Everything ``JSCoup(...)`` accepts
        can still be passed through ``**kwargs``.
        """
        bl = cls(
            service_name=service_name or _guess_service_name(app),
            dashboard_username=dashboard_username,
            dashboard_password=dashboard_password,
            **kwargs,
        )
        bl.watch_sqlite()
        if app is not None:
            bl.install(app)
        return bl

    @classmethod
    def from_config_file(
        cls, app: Any = None, path: Optional[str] = None, **overrides: Any
    ) -> "JSCoup":
        """Build a :class:`JSCoup` from one project config file instead of
        keyword arguments — see :mod:`jscoup.projectconfig`. Created
        automatically, with a generated superadmin password already filled
        in, the first time it's loaded and the file doesn't exist.

        ``bl = JSCoup.from_config_file(app)`` covers the database JSCoup
        itself uses (SQLite by default, or a real SQL database via
        ``database_url`` in the file — see :mod:`jscoup.storage.sql`), the
        dashboard admin login, and installs into ``app`` if one is given.
        Anything in ``**overrides`` wins over the file, exactly like passing
        it to ``JSCoup(...)`` directly. The loaded/created
        :class:`~jscoup.projectconfig.ProjectConfig` stays reachable as
        ``bl.project_config`` — use it to decide how/where to call
        :meth:`run_dashboard` yourself (it is *not* started automatically:
        binding a port at config-load time would break import-time use, the
        same reason ``run_dashboard`` is never called implicitly elsewhere).
        """
        from . import projectconfig

        project_config = projectconfig.load_or_create(path or projectconfig.DEFAULT_CONFIG_PATH)

        # Pop, not read: `storage` must only be passed to the constructor once.
        storage: Optional[BaseStorage] = overrides.pop("storage", None)
        if storage is None and project_config.database_url:
            from .storage.sql import SqlStorage

            storage = SqlStorage(
                project_config.database_url,
                max_events=overrides.get("max_events"),
                retention_days=overrides.get("retention_days", project_config.retention_days),
            )

        kwargs: Dict[str, Any] = dict(
            service_name=project_config.service_name,
            environment=project_config.environment,
            db_path=project_config.db_path,
            retention_days=project_config.retention_days,
            dashboard_username=project_config.dashboard_username,
            dashboard_password=project_config.dashboard_password,
            dashboard_mount_in_app=project_config.dashboard_mount_in_app,
            dashboard_allowed_ips=project_config.dashboard_allowed_ips,
            gateway_enabled=project_config.features.get("gateway", False),
            gateway_token_ttl_hours=project_config.gateway_token_ttl_hours,
            encryption_key=project_config.encryption_key,
        )
        # Feature flags whose config-file name differs from the JSCoupConfig
        # field they control (e.g. features.live_tester -> allow_live_invoke).
        for feature_name, config_field in projectconfig.FEATURE_TO_CONFIG_FIELD.items():
            if feature_name in project_config.features:
                kwargs[config_field] = project_config.features[feature_name]
        kwargs.update(overrides)
        bl = cls(storage=storage, **kwargs)
        bl.project_config = project_config
        if app is not None:
            bl.install(app)
        return bl

    # ------------------------------------------------------------------ #
    # capture
    # ------------------------------------------------------------------ #

    @contextmanager
    def capture(
        self,
        kind: str = KIND_SERVICE,
        name: str = "",
        reraise: bool = True,
        params: Optional[Dict[str, Any]] = None,
        actor: Optional[Actor] = None,
        tags: Optional[Dict[str, Any]] = None,
        simulation_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        **meta: Any,
    ):
        """Capture whatever happens inside the block.

        Yields the live :class:`~jscoup.context.CaptureContext` so the caller
        can attach extra data (``ctx.set_tag``, ``ctx.status_code = ...``).
        """
        if not self.config.enabled:
            ctx = CaptureContext(kind, name)
            yield ctx
            return

        parent = current_context()
        ctx = CaptureContext(
            kind=kind,
            name=name,
            parent_id=parent.id if parent else None,
            max_breadcrumbs=self.config.max_breadcrumbs,
            max_queries=self.config.max_queries,
            max_stdout_chars=self.config.max_print_chars,
        )
        ctx.suppressed = not self._sample_call()
        ctx.capture_query_caller = self.config.capture_query_caller
        ctx.params = dict(params or {})
        ctx.actor = actor
        ctx.tags = dict(tags or {})
        ctx.meta = dict(meta or {})
        ctx.simulation_id = simulation_id
        ctx.trace_id = trace_id or (parent.trace_id if parent else None)
        push(ctx)
        try:
            yield ctx
        except BaseException as exc:  # noqa: BLE001
            self.finish(ctx, exception=exc)
            # reraise=False must not swallow a cancellation/interrupt.
            if reraise or isinstance(exc, _NEVER_SWALLOW):
                raise
        else:
            self.finish(ctx)
        finally:
            pop(ctx)

    def _sample_call(self):
        import random
        return self.config.enabled and (self.config.sample_rate == 1 or random.random() < self.config.sample_rate)

    def begin(self, kind: str = KIND_HTTP, name: str = "", _sampled: bool = False, **fields: Any) -> CaptureContext:
        """Open a context manually (used by middlewares). Pair with :meth:`end`."""
        parent = current_context()
        ctx = CaptureContext(
            kind=kind,
            name=name,
            parent_id=parent.id if parent else None,
            max_breadcrumbs=self.config.max_breadcrumbs,
            max_queries=self.config.max_queries,
            max_stdout_chars=self.config.max_print_chars,
        )
        for key, value in fields.items():
            if hasattr(ctx, key):
                setattr(ctx, key, value)
            else:
                ctx.meta[key] = value
        ctx.suppressed = not _sampled and not self._sample_call()
        ctx.capture_query_caller = self.config.capture_query_caller
        push(ctx)
        return ctx

    def end(
        self, ctx: Optional[CaptureContext], exception: Optional[BaseException] = None
    ) -> Optional[EventRecord]:
        """Close a context opened with :meth:`begin` and store the event."""
        if ctx is None:
            return None
        try:
            return self.finish(ctx, exception=exception)
        finally:
            pop(ctx)

    def finish(self, ctx: CaptureContext, exception: Optional[BaseException] = None) -> Optional[EventRecord]:
        """Turn a finished context into an analysed, stored event.

        Both ``capture()`` and ``end()`` funnel through here, so the
        ``enabled`` flag only needs to be checked in this one place.
        """
        if self._closed or not self.config.enabled or ctx.suppressed:
            return None
        try:
            event = self._build_event(ctx, exception, include_success=True)
        except Exception:  # capture must never break the host application
            return None
        if event is None:
            return None
        return self._store(event, record_call=True)

    def record_exception(
        self,
        exception: BaseException,
        name: Optional[str] = None,
        kind: str = KIND_SERVICE,
        **meta: Any,
    ) -> Optional[EventRecord]:
        """Record an exception that was caught somewhere else."""
        ctx = current_context()
        if ctx is not None:
            ctx.meta.update(meta)
            return self.finish(ctx, exception=exception)
        standalone = CaptureContext(kind, name or type(exception).__name__)
        standalone.meta.update(meta)
        return self.finish(standalone, exception=exception)

    def note(self, message: str, category: str = "note", level: str = SEVERITY_INFO, **data: Any) -> None:
        """Add a breadcrumb to the current operation."""
        add_breadcrumb(message, category=category, level=level, **data)

    def identify(self, token: Optional[str] = None, **fields: Any) -> Optional[Actor]:
        """Attach an actor to the current operation."""
        ctx = current_context()
        actor = self.identity.resolve(token) if token else Actor()
        for key, value in fields.items():
            setattr(actor, key, value) if hasattr(actor, key) else actor.claims.update({key: value})
        if ctx is not None:
            ctx.actor = actor
        return actor

    # ------------------------------------------------------------------ #
    # decorators
    # ------------------------------------------------------------------ #

    def watch(
        self,
        name: Optional[str] = None,
        kind: str = KIND_SERVICE,
        reraise: bool = True,
        fallback: Any = None,
        register: bool = True,
        tags: Optional[Dict[str, Any]] = None,
        description: str = "",
        capture_args: bool = True,
        healthcheck_allowed: bool = False,
    ) -> Callable:
        """Wrap a function so every call is captured (sync or async).

        ``register=True`` also publishes the function in the dashboard's live
        tester. ``healthcheck_allowed=True`` opts it into ``check_apis()``'s
        automatic sweep; off by default since a zero-argument function isn't
        necessarily side-effect-free.
        """

        def decorator(func: Callable) -> Callable:
            label = name or f"{func.__module__}.{func.__qualname__}"

            if register:
                self.registry.register_callable(
                    func, name=label, kind=kind, description=description,
                    tags=list((tags or {}).keys()), healthcheck_allowed=healthcheck_allowed,
                )

            if inspect.iscoroutinefunction(func):

                @functools.wraps(func)
                async def async_wrapper(*args: Any, **kwargs: Any):
                    if not self._sample_call():
                        try:return await func(*args, **kwargs)
                        except BaseException as exc:
                            if reraise or isinstance(exc, _NEVER_SWALLOW):raise
                            return fallback
                    params = self._bind_params(func, args, kwargs) if capture_args else {}
                    ctx = self.begin(kind=kind, name=label, params=params, tags=dict(tags or {}), _sampled=True)
                    try:
                        result = await func(*args, **kwargs)
                    except BaseException as exc:
                        self.end(ctx, exception=exc)
                        if reraise or isinstance(exc, _NEVER_SWALLOW):
                            raise
                        return fallback
                    ctx.result_preview = self._preview(result)
                    self.end(ctx)
                    return result

                async_wrapper.__jscoup_target__ = f"service:{label}"  # type: ignore[attr-defined]
                return async_wrapper

            @functools.wraps(func)
            def wrapper(*args: Any, **kwargs: Any):
                if not self._sample_call():
                    try:return func(*args, **kwargs)
                    except BaseException as exc:
                        if reraise or isinstance(exc, _NEVER_SWALLOW):raise
                        return fallback
                params = self._bind_params(func, args, kwargs) if capture_args else {}
                ctx = self.begin(kind=kind, name=label, params=params, tags=dict(tags or {}), _sampled=True)
                try:
                    result = func(*args, **kwargs)
                except BaseException as exc:
                    self.end(ctx, exception=exc)
                    if reraise or isinstance(exc, _NEVER_SWALLOW):
                        raise
                    return fallback
                ctx.result_preview = self._preview(result)
                self.end(ctx)
                return result

            wrapper.__jscoup_target__ = f"service:{label}"  # type: ignore[attr-defined]
            return wrapper

        return decorator

    def service(self, name: Optional[str] = None, **kwargs: Any) -> Callable:
        """Alias of :meth:`watch` with ``kind='service'``."""
        return self.watch(name=name, kind=KIND_SERVICE, **kwargs)

    def task(self, name: Optional[str] = None, **kwargs: Any) -> Callable:
        return self.watch(name=name, kind=KIND_TASK, **kwargs)

    def watch_module(
        self,
        module: Any,
        kind: str = KIND_SERVICE,
        recursive: bool = False,
        include: Optional[Iterable[str]] = None,
        exclude: Optional[Iterable[str]] = None,
    ) -> int:
        """Wrap every function defined in ``module`` with :meth:`watch`.
        ``module`` may be a module object or an importable dotted name.

        Only functions whose ``__module__`` matches ``module`` are wrapped;
        already-wrapped functions and names starting with ``_`` are skipped
        unless listed in ``include``. Pass ``recursive=True`` to also walk
        every submodule of a package.

        Call this right after importing ``module`` and before any
        ``from module import some_function`` elsewhere, since Python copies
        the name binding at import time and a wrap afterwards won't reach it.
        """
        if isinstance(module, str):
            import importlib

            module = importlib.import_module(module)

        include_set = set(include) if include is not None else None
        exclude_set = set(exclude) if exclude is not None else set()
        wrapped = 0
        for name, obj in list(vars(module).items()):
            if include_set is not None and name not in include_set:
                continue
            if include_set is None and name.startswith("_"):
                continue
            if name in exclude_set:
                continue
            if getattr(obj, "__module__", None) != module.__name__:
                continue  # defined elsewhere, just imported into this module
            if inspect.isclass(obj):
                wrapped += self.watch_class(obj, kind=kind)
                continue
            if not (inspect.isfunction(obj) or inspect.iscoroutinefunction(obj)):
                continue
            if getattr(obj, "__jscoup_target__", None):
                continue  # already wrapped
            label = f"{module.__name__}.{name}"
            setattr(module, name, self.watch(name=label, kind=kind)(obj))
            wrapped += 1

        if recursive and hasattr(module, "__path__"):
            import importlib
            import pkgutil

            for _, subname, _ in pkgutil.iter_modules(module.__path__, module.__name__ + "."):
                submodule = importlib.import_module(subname)
                wrapped += self.watch_module(
                    submodule, kind=kind, recursive=True, include=include, exclude=exclude
                )
        return wrapped

    def watch_class(
        self,
        cls: type,
        kind: str = KIND_SERVICE,
        include: Optional[Iterable[str]] = None,
        exclude: Optional[Iterable[str]] = None,
    ) -> int:
        """Wrap every plain method defined directly on ``cls`` with
        :meth:`watch` — the class-level counterpart of :meth:`watch_module`.

        Only methods in ``vars(cls)`` itself are wrapped, so a subclass never
        re-wraps its parent's methods. ``@staticmethod``/``@classmethod``
        members and dunders are skipped unless named in ``include``. Safe to
        call more than once.

        The dashboard's Live Tester cannot invoke one of these directly the
        way it can a module-level function, since there is no instance to
        construct.
        """
        include_set = set(include) if include is not None else None
        exclude_set = set(exclude) if exclude is not None else set()
        wrapped = 0
        for name, obj in list(vars(cls).items()):
            if include_set is not None and name not in include_set:
                continue
            if include_set is None and name.startswith("_"):
                continue
            if name in exclude_set:
                continue
            if not inspect.isfunction(obj):  # excludes staticmethod/classmethod descriptors
                continue
            if getattr(obj, "__jscoup_target__", None):
                continue
            label = f"{cls.__module__}.{cls.__qualname__}.{name}"
            setattr(cls, name, self.watch(name=label, kind=kind)(obj))
            wrapped += 1
        return wrapped

    # ------------------------------------------------------------------ #
    # serverless / service simulation
    # ------------------------------------------------------------------ #

    def simulate_lambda(
        self,
        handler: Callable[..., Any],
        event: Optional[Dict[str, Any]] = None,
        context: Any = None,
        name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Run a Lambda-style ``handler(event, context)`` under capture.

        Returns ``{"ok", "result"|"error", "event_id"}`` instead of raising, so
        it can be driven from a test or from the dashboard.
        """
        label = name or f"lambda:{getattr(handler, '__name__', 'handler')}"
        payload = event or {}
        lambda_context = context or LambdaContext(function_name=label)
        ctx = self.begin(kind=KIND_LAMBDA, name=label, params={"event": payload})
        try:
            result = handler(payload, lambda_context)
        except Exception as exc:
            self.end(ctx, exception=exc)
            return {"ok": False, "error": f"{type(exc).__name__}: {exc}", "event_id": ctx.id}
        ctx.result_preview = self._preview(result)
        self.end(ctx)
        return {"ok": True, "result": result, "event_id": ctx.id}

    def watch_lambda(self, name: Optional[str] = None) -> Callable:
        """Decorator for a real, deployed ``handler(event, context)`` —
        every invocation is captured, and the handler is registered so it
        shows up in Check-APIs/Live-Tester like any other target::

            @bl.watch_lambda()
            def handler(event, context):
                ...
        """

        def decorator(handler: Callable[..., Any]) -> Callable[..., Any]:
            label = name or f"lambda:{getattr(handler, '__name__', 'handler')}"
            self.registry.register_callable(
                handler, name=label, kind=KIND_LAMBDA,
                description=(inspect.getdoc(handler) or "").split("\n")[0],
            )

            @functools.wraps(handler)
            def wrapper(event: Any = None, context: Any = None, *args: Any, **kwargs: Any) -> Any:
                ctx = self.begin(kind=KIND_LAMBDA, name=label, params={"event": event})
                try:
                    result = handler(event, context, *args, **kwargs)
                except BaseException as exc:
                    self.end(ctx, exception=exc)
                    raise
                ctx.result_preview = self._preview(result)
                self.end(ctx)
                return result

            wrapper.__jscoup_target__ = f"service:{label}"  # type: ignore[attr-defined]
            return wrapper

        return decorator

    def watch_azure_function(self, name: Optional[str] = None) -> Callable:
        """Decorator for a real, deployed Azure Functions HTTP handler —
        ``def handler(req: azure.functions.HttpRequest) -> azure.functions.HttpResponse``
        (both the v1 and v2 styles use this signature)::

            @bl.watch_azure_function()
            def main(req: func.HttpRequest) -> func.HttpResponse:
                ...

        Duck-typed on purpose so it never needs the ``azure-functions``
        package installed to import this module.
        """

        def decorator(handler: Callable[..., Any]) -> Callable[..., Any]:
            label = name or f"azure:{getattr(handler, '__name__', 'function')}"
            self.registry.register_callable(
                handler, name=label, kind=KIND_AZURE_FUNCTION,
                description=(inspect.getdoc(handler) or "").split("\n")[0],
            )

            @functools.wraps(handler)
            def wrapper(req: Any, *args: Any, **kwargs: Any) -> Any:
                from .serverless import azure_request_fields, azure_response_status

                fields = azure_request_fields(req)
                ctx = self.begin(kind=KIND_AZURE_FUNCTION, name=label, method=fields["method"],
                                  path=fields["url"])
                if self.config.capture_headers:
                    ctx.headers = self.redactor.scrub_headers(fields["headers"])
                ctx.params = dict(fields["query_params"])
                if fields["body_json"] is not None and isinstance(fields["body_json"], dict):
                    ctx.params.update(self.redactor.scrub(fields["body_json"]))
                if fields["body_text"] is not None:
                    ctx.body_preview = self.redactor.scrub_body(fields["body_text"], self.config.body_preview_chars)
                try:
                    result = handler(req, *args, **kwargs)
                except BaseException as exc:
                    self.end(ctx, exception=exc)
                    raise
                ctx.status_code = azure_response_status(result)
                ctx.result_preview = self._preview(result)
                self.end(ctx)
                return result

            @functools.wraps(handler)
            async def async_wrapper(req: Any, *args: Any, **kwargs: Any) -> Any:
                from .serverless import azure_request_fields, azure_response_status

                fields = azure_request_fields(req)
                ctx = self.begin(kind=KIND_AZURE_FUNCTION, name=label, method=fields["method"],
                                  path=fields["url"])
                if self.config.capture_headers:
                    ctx.headers = self.redactor.scrub_headers(fields["headers"])
                ctx.params = dict(fields["query_params"])
                if fields["body_json"] is not None and isinstance(fields["body_json"], dict):
                    ctx.params.update(self.redactor.scrub(fields["body_json"]))
                if fields["body_text"] is not None:
                    ctx.body_preview = self.redactor.scrub_body(fields["body_text"], self.config.body_preview_chars)
                try:
                    result = await handler(req, *args, **kwargs)
                except BaseException as exc:
                    self.end(ctx, exception=exc)
                    raise
                ctx.status_code = azure_response_status(result)
                ctx.result_preview = self._preview(result)
                self.end(ctx)
                return result

            if inspect.iscoroutinefunction(handler):
                wrapper = async_wrapper

            wrapper.__jscoup_target__ = f"service:{label}"  # type: ignore[attr-defined]
            return wrapper

        return decorator

    def watch_oci_function(self, name: Optional[str] = None) -> Callable:
        """Decorator for a real, deployed OCI (Oracle Cloud) Function built on
        the Fn Project Python FDK — ``def handler(ctx, data: io.BytesIO = None)``::

            from fdk import response

            @bl.watch_oci_function()
            def handler(ctx, data=None):
                ...
                return response.Response(ctx, response_data=..., headers=...)

        Duck-typed on purpose so it never needs the ``fdk`` package installed
        to import this module.
        """

        def decorator(handler: Callable[..., Any]) -> Callable[..., Any]:
            label = name or f"oci:{getattr(handler, '__name__', 'function')}"
            self.registry.register_callable(
                handler, name=label, kind=KIND_OCI_FUNCTION,
                description=(inspect.getdoc(handler) or "").split("\n")[0],
            )

            @functools.wraps(handler)
            def wrapper(ctx: Any, data: Any = None, *args: Any, **kwargs: Any) -> Any:
                from .serverless import oci_request_fields, oci_response_status

                fields = oci_request_fields(ctx, data)
                call_ctx = self.begin(kind=KIND_OCI_FUNCTION, name=label, trace_id=fields["call_id"])
                if self.config.capture_headers:
                    call_ctx.headers = self.redactor.scrub_headers(fields["headers"])
                if fields["body_json"] is not None and isinstance(fields["body_json"], dict):
                    call_ctx.params = self.redactor.scrub(fields["body_json"])
                if fields["body_text"] is not None:
                    call_ctx.body_preview = self.redactor.scrub_body(fields["body_text"], self.config.body_preview_chars)
                try:
                    result = handler(ctx, data, *args, **kwargs)
                except BaseException as exc:
                    self.end(call_ctx, exception=exc)
                    raise
                call_ctx.status_code = oci_response_status(result)
                call_ctx.result_preview = self._preview(result)
                self.end(call_ctx)
                return result

            wrapper.__jscoup_target__ = f"service:{label}"  # type: ignore[attr-defined]
            return wrapper

        return decorator

    def register_target(self, target: Target) -> Target:
        return self.registry.add(target)

    def invoke(self, target_id: str, params: Optional[Dict[str, Any]] = None,
               token: Optional[str] = None, base_url: Optional[str] = None) -> Dict[str, Any]:
        """Replay a catalogued HTTP API over the network — the programmatic twin
        of the live tester. ``token`` is sent as ``Authorization: Bearer``.
        JSCoup never runs application code itself, so a target that is not an
        HTTP API (a watched function) is refused with ``ok=False``."""
        return self.simulator.invoke(target_id, params=params, token=token, base_url=base_url)

    async def ainvoke(self, target_id: str, params: Optional[Dict[str, Any]] = None,
                       token: Optional[str] = None, base_url: Optional[str] = None) -> Dict[str, Any]:
        """Async counterpart of :meth:`invoke`: the blocking HTTP replay runs in
        a worker thread so the caller's event loop is not blocked."""
        return await self.simulator.ainvoke(target_id, params=params, token=token, base_url=base_url)

    # ------------------------------------------------------------------ #
    # instrumentation helpers
    # ------------------------------------------------------------------ #

    def watch_sqlite(self, global_patch: bool = True) -> None:
        """Trace every ``sqlite3`` connection opened from now on."""
        if global_patch:
            instrument_sqlite3()

    def watch_sqlalchemy(self, engine: Any) -> None:
        instrument_sqlalchemy(engine)

    def record_query(self, sql: str, params: Any = None, duration_ms: float = 0.0,
                     error: Optional[str] = None, backend: str = "custom") -> None:
        emit_query(sql, params, duration_ms, error=error, backend=backend)

    # ------------------------------------------------------------------ #
    # framework installation
    # ------------------------------------------------------------------ #

    def install(self, app: Any = None, mount_path: Optional[str] = None, **kwargs: Any) -> Any:
        """Detect the framework and wire middleware + dashboard.

        Supported: Flask, FastAPI/Starlette, Django (pass ``app=None`` and add
        ``JSCoupMiddleware`` to ``MIDDLEWARE`` instead, or call
        :meth:`install_django`).
        """
        mount = mount_path or self.config.mount_path
        module = type(app).__module__ if app is not None else ""

        if app is not None and module.startswith("flask"):
            from .integrations.flask import install_flask

            self._installed_apps.append("flask")
            return install_flask(app, self, mount, **kwargs)

        if app is not None and (module.startswith("fastapi") or module.startswith("starlette")):
            from .integrations.fastapi import install_fastapi

            self._installed_apps.append("fastapi")
            return install_fastapi(app, self, mount, **kwargs)

        if app is None or module.startswith("django"):
            return self.install_django(mount, **kwargs)

        raise TypeError(
            f"Unsupported application object: {type(app)!r}. "
            "Use install_flask/install_fastapi/install_django directly."
        )

    def install_django(self, mount_path: Optional[str] = None, **kwargs: Any) -> Any:
        from .integrations.django import install_django

        self._installed_apps.append("django")
        return install_django(self, mount_path or self.config.mount_path, **kwargs)

    def refresh_targets(self) -> int:
        """Re-scan the installed app's routes right now.

        ``install(app)`` snapshots routes once, at call time, so a route
        added afterwards would otherwise stay invisible. The dashboard calls
        this before every request it serves. Safe to call any time; a no-op
        before anything is installed.

        Also re-applies the gateway's manually-catalogued targets and its
        disabled-target list to this process's own Registry, if the gateway
        is enabled — those live in GatewayStore's shared database (see its
        module docstring) precisely so that every worker process converges
        to the same view on its next request, the same way route discovery
        already does.
        """
        if self.config.gateway_enabled:
            try:
                gw = self.gateway
                for manual in gw.list_manual_targets():
                    self.registry.add_manual(
                        manual["method"], manual["path"], name=manual["name"], description=manual["description"] or ""
                    )
                self.registry.sync_disabled(gw.disabled_target_ids())
                for target_id, description in gw.get_target_descriptions().items():
                    self.registry.set_description(target_id, description)
            except Exception:
                pass

        source = self._route_source
        if not source:
            return 0
        framework = source.get("framework")
        try:
            if framework == "fastapi":
                return self.registry.discover_fastapi(source["app"], source["mount"])
            if framework == "flask":
                return self.registry.discover_flask(source["app"], source["mount"])
            if framework == "django":
                return self.registry.discover_django(source["mount"])
        except Exception:
            pass  # discovery must never break the dashboard it feeds
        return 0

    def describe(
        self,
        path: Optional[str] = None,
        method: str = "GET",
        *,
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
        """Write a human description for an API or a watched service, shown
        in the dashboard's Live Tester. Can be called anywhere, any time,
        relative to ``install()``/``watch_module()``::

            bl.describe("/api/v1/users", method="POST",
                        description="Create a user account.",
                        params={"email": "the user's login email"})

        Pass ``healthcheck_allowed=True`` to opt an auto-discovered HTTP
        target into ``check_apis()``'s automatic sweep. ``request_example``
        (a JSON body), ``response_examples`` (``{status: body}``) and
        ``params_example`` (``{param: value}``) replace the automatically
        derived examples shown on the docs page and in exports.
        """
        self.registry.describe(
            method=method if path else None,
            path=path,
            name=name,
            description=description,
            full_description=full_description,
            params=params,
            healthcheck_allowed=healthcheck_allowed,
            tags=tags,
            request_example=request_example,
            response_examples=response_examples,
            params_example=params_example,
        )

    @property
    def dashboard(self):
        from .dashboard.api import DashboardAPI

        with self._aux_lock:
            if not hasattr(self, "_dashboard"):
                self._dashboard = DashboardAPI(self)
            return self._dashboard

    @property
    def gateway(self):
        """Lazily-built :class:`~jscoup.gateway.GatewayStore`."""
        from .gateway import GatewayStore

        with self._aux_lock:
            if not hasattr(self, "_gateway"):
                self._gateway = GatewayStore(
                    self.config.gateway_db_path, token_ttl_hours=self.config.gateway_token_ttl_hours,
                    realm=str(self.config.auth_realm_id or (self.config.service_name, self.config.environment)),
                    encryption_key=self.config.encryption_key
                )
            return self._gateway

    @property
    def call_log(self):
        """Lazily-built :class:`~jscoup.calllog.CallLogStore`."""
        from .calllog import CallLogStore

        with self._aux_lock:
            if not hasattr(self, "_call_log"):
                self._call_log = CallLogStore(self.config.call_log_db_path, max_rows=self.config.call_log_max_rows)
            return self._call_log

    def _record_safe_call(self, event):
        # No actor, request body, concrete URL, or historical response is
        # duplicated into this lightweight statistics store.
        row = dict(kind=event.kind, name=event.name, method=event.method,
                   path=None, status_code=event.status_code,
                   ok=event.status == STATUS_OK, duration_ms=event.duration_ms,
                   actor=None, response_preview=None)
        try:
            if self.config.async_storage:
                self._call_publisher.submit(row)
            else:
                self.call_log.record(**row)
                self._maybe_purge_call_log()
        except Exception:
            self._storage_failures += 1

    @property
    def _call_publisher(self):
        with self._aux_lock:
            if not hasattr(self, "_call_writer"):
                from .publisher import EventPublisher
                from .calllog import CallLogSink
                self._call_writer = EventPublisher(CallLogSink(self.call_log, self.config.call_log_retention_days), self.config.event_queue_size)
            return self._call_writer

    def _maybe_purge_call_log(self) -> None:
        now = time.monotonic()
        if now - getattr(self, "_last_call_log_purge", -3600.0) < 3600:
            return
        self._last_call_log_purge = now
        days = self.config.call_log_retention_days
        if days and days > 0:
            self.call_log.purge_older_than(time.time() - days * 86400)

    @property
    def dashboard_path(self) -> str:
        return self.config.mount_path

    def run_dashboard(
        self,
        host: str = "127.0.0.1",
        port: int = 9000,
        background: bool = True,
        base_url: Optional[str] = None,
        **kwargs: Any,
    ) -> Any:
        """Serve the dashboard as its own standalone server on ``host:port``,
        sharing this same ``JSCoup`` instance's registry, storage and
        simulator. Pass ``base_url`` (e.g. ``"http://127.0.0.1:5000"``) so
        the live tester can replay HTTP targets.
        """
        if self._dashboard_server is not None:
            return self._dashboard_server
        if base_url and not self.config.base_url:
            self.config.base_url = base_url
        from .integrations.standalone import run_standalone_dashboard

        self._dashboard_server = run_standalone_dashboard(
            self, host=host, port=port, background=background, **kwargs
        )
        return self._dashboard_server

    def audit_code(self, paths: Optional[List[str]] = None) -> List[Any]:
        """Scan ``paths`` (default: the current working directory) for naming/style
        issues, plus collisions among registered HTTP route targets."""
        from .audit import audit_code

        return audit_code(paths=paths or [os.getcwd()], registry=self.registry)

    def check_apis(
        self, token: Optional[str] = None, base_url: Optional[str] = None, include_params: bool = False
    ) -> List[Any]:
        """Call every registered target that needs no required parameters and
        report pass/fail plus a response preview for each. Pass ``token`` to
        apply it to every protected target in one sweep."""
        from .healthcheck import check_apis

        return check_apis(
            self.registry,
            self.simulator,
            self.storage,
            token=token,
            base_url=base_url or self.config.base_url,
            include_params=include_params,
        )

    # ------------------------------------------------------------------ #
    # internals
    # ------------------------------------------------------------------ #

    def _bind_params(self, func: Callable, args: tuple, kwargs: dict) -> Dict[str, Any]:
        try:
            bound = inspect.signature(func).bind_partial(*args, **kwargs)
            bound.apply_defaults()
            return {k: _shallow(v) for k, v in bound.arguments.items() if k not in ("self", "cls")}
        except (TypeError, ValueError):
            return {"args": [_shallow(a) for a in args], "kwargs": {k: _shallow(v) for k, v in kwargs.items()}}

    def _preview(self, value: Any) -> str:
        # A custom __repr__ can raise; that must not turn a success into a
        # reported crash.
        try:
            text = repr(value)
        except Exception:
            text = f"<{type(value).__name__}: repr() failed>"
        return self.redactor.scrub_text(text, self.config.body_preview_chars)

    def _scrub_query_string(self, query_string: Optional[str]) -> Optional[str]:
        """Mask sensitive values (``?token=...``, ``?api_key=...``) in a raw
        query string, matched by key rather than by the shape of the value."""
        if not query_string:
            return query_string
        try:
            pairs = parse_qsl(query_string, keep_blank_values=True)
        except ValueError:
            return self.redactor.scrub_text(query_string)
        scrubbed = [
            (key, self.redactor.mask if self.redactor.is_sensitive(key) else self.redactor.scrub_text(value))
            for key, value in pairs
        ]
        return urlencode(scrubbed)

    def _scrub_breadcrumb(self, crumb: Breadcrumb) -> Breadcrumb:
        """Return a scrubbed copy; never mutate the caller's own Breadcrumb."""
        return Breadcrumb(
            ts=crumb.ts,
            category=crumb.category,
            message=self.redactor.scrub_text(crumb.message),
            data=self.redactor.scrub(crumb.data),
            level=crumb.level,
        )

    def _scrub_actor(self, actor: Optional[Actor]) -> Optional[Actor]:
        """Return a scrubbed copy of ``actor``; its ``claims`` come from a
        decoded JWT, a static token, or a custom identity resolver, so they
        get the same redaction as any other captured dict."""
        if actor is None:
            return None
        scrubbed = copy.copy(actor)
        scrubbed.claims = self.redactor.scrub(actor.claims)
        return scrubbed

    def _build_event(self, ctx: CaptureContext, exception: Optional[BaseException], include_success=False) -> Optional[EventRecord]:
        duration = ctx.elapsed_ms
        performance = self._performance_signals(ctx, duration)

        status = STATUS_OK
        if exception is not None:
            status = STATUS_ERROR
        elif ctx.status_code and ctx.status_code >= 500 and self.config.capture_5xx:
            status = STATUS_ERROR
        elif ctx.status_code in (401, 403) and self.config.capture_auth_failures:
            # Captured independent of capture_4xx even with no raised exception.
            status = STATUS_ERROR
        elif ctx.status_code and 400 <= ctx.status_code < 500 and self.config.capture_4xx:
            status = STATUS_ERROR
        elif performance:
            status = STATUS_SLOW

        if status == STATUS_OK and not self.config.capture_success and not include_success:
            return None
        if ctx.suppressed:
            return None
        if self._is_ignored(ctx, exception):
            return None

        error_type = type(exception).__name__ if exception else None
        error_module = type(exception).__module__ if exception else None
        error_message = self.redactor.scrub_text(str(exception), 2000) if exception else None
        tb_text = self._format_traceback(exception) if exception else None
        culprit, culprit_line = self._culprit(exception) if exception else ("", "")

        data = AnalysisInput(
            exception=exception,
            error_type=error_type or "",
            error_module=error_module or "",
            error_message=error_message or "",
            traceback_text=tb_text or "",
            culprit=culprit or "",
            culprit_line=culprit_line or "",
            kind=ctx.kind,
            name=ctx.name,
            status_code=ctx.status_code or _exception_status_code(exception),
            duration_ms=duration,
            queries=list(ctx.queries),
            params=ctx.params,
            meta={**ctx.meta, "performance": performance},
        )
        diagnosis: Optional[Diagnosis] = None
        if status != STATUS_OK:
            diagnosis = self.analyzers.analyze(data)

        event = EventRecord(
            id=ctx.id,
            ts=time.time(),
            kind=ctx.kind,
            name=ctx.name or ctx.path or "unnamed",
            status=status,
            severity=(diagnosis.severity if diagnosis else
                      (SEVERITY_ERROR if status == STATUS_ERROR else
                       SEVERITY_WARNING if status == STATUS_SLOW else SEVERITY_INFO)),
            category=diagnosis.category if diagnosis else "none",
            method=ctx.method,
            path=ctx.path,
            route=ctx.route,
            query_string=self._scrub_query_string(ctx.query_string),
            status_code=ctx.status_code,
            client_ip=ctx.client_ip,
            duration_ms=duration,
            error_type=error_type,
            error_module=error_module,
            error_message=error_message,
            traceback_text=tb_text,
            culprit=culprit,
            culprit_line=culprit_line or None,
            stdout_capture=self.redactor.scrub_text(ctx.stdout_text) if ctx.stdout_text else None,
            fingerprint=build_fingerprint(error_type or f"{status}:{ctx.name}",
                                          error_message or ctx.name, culprit or ""),
            params=self.redactor.scrub(ctx.params),
            # Redacted again here as a safety net regardless of which capture
            # path set these fields; scrub_text on already-scrubbed text is a
            # safe no-op.
            headers=self.redactor.scrub_headers(ctx.headers) if self.config.capture_headers else {},
            body_preview=self.redactor.scrub_text(ctx.body_preview) if ctx.body_preview else ctx.body_preview,
            response_preview=(
                self.redactor.scrub_text(ctx.response_preview) if ctx.response_preview else ctx.response_preview
            ),
            result_preview=ctx.result_preview,
            actor=self._scrub_actor(ctx.actor),
            queries=list(ctx.queries),
            total_query_count=ctx.query_total,
            total_db_time_ms=ctx.query_duration,
            queries_dropped=ctx.queries_dropped,
            breadcrumbs=[self._scrub_breadcrumb(b) for b in ctx.breadcrumbs],
            diagnosis=diagnosis,
            tags=self.redactor.scrub(ctx.tags),
            meta=self.redactor.scrub({k: _shallow(v) for k, v in ctx.meta.items()}),
            parent_id=ctx.parent_id,
            trace_id=ctx.trace_id,
            simulation_id=ctx.simulation_id,
            service=self.config.service_name,
            environment=self.config.environment,
            release=self.config.release,
            host=self.host,
        )
        return event

    def _store(self, event: EventRecord, record_call=False) -> Optional[EventRecord]:
        try:
            event = self._sanitizer.clean(event)
        except Exception:
            return None
        if self.config.before_store:
            try:
                modified = self.config.before_store(event)
                if modified is None:
                    return None
                event = modified
            except Exception:
                # If before_store raises, drop the event rather than storing
                # the unsanitized original — a broken hook must not bypass
                # the app's own data-handling policy.
                self._before_store_failures += 1
                return None
        try:
            if self.config.before_store:
                event = self._sanitizer.clean(event)
            if record_call and self.config.call_log_enabled:
                self._record_safe_call(event)
            if record_call and event.status == STATUS_OK and not self.config.capture_success:
                return None
            if self._publisher:
                return event if self._publisher.submit(event) else None
            self.storage.save(event)
        except Exception:
            self._storage_failures += 1
            return None
        if self.config.on_event:
            try:
                self.config.on_event(event)
            except Exception:
                pass
        return event

    def _performance_signals(self, ctx: CaptureContext, duration: float) -> Dict[str, Any]:
        if not self.config.capture_slow:
            return {}
        signals: Dict[str, Any] = {}
        if duration >= self.config.slow_request_ms:
            signals["slow_request_ms"] = round(duration, 2)
        counts: Dict[str, int] = {}
        for query in ctx.queries:
            key = normalize_sql(query.sql)
            counts[key] = counts.get(key, 0) + 1
        if counts:
            sql, count = max(counts.items(), key=lambda kv: kv[1])
            if count >= self.config.n_plus_one_threshold:
                signals["n_plus_one"] = {"sql": sql, "count": count}
        slow_queries = [q for q in ctx.queries if q.duration_ms >= self.config.slow_query_ms]
        if slow_queries:
            signals["slow_queries"] = len(slow_queries)
        return signals

    def _is_ignored(self, ctx: CaptureContext, exception: Optional[BaseException]) -> bool:
        if exception is not None and self.config.ignored_exceptions:
            names = {type(exception).__name__, f"{type(exception).__module__}.{type(exception).__name__}"}
            if names & set(self.config.ignored_exceptions):
                return True
        path = ctx.path or ""
        return any(path.startswith(prefix) for prefix in self.config.ignored_paths)

    def _format_traceback(self, exception: BaseException) -> str:
        lines = traceback.format_exception(
            type(exception), exception, exception.__traceback__, limit=self.config.traceback_limit
        )
        return self.redactor.scrub_text("".join(lines), 20000)

    @staticmethod
    def _culprit(exception: BaseException) -> "tuple[str, str]":
        """Return ``(formatted culprit, exact source line)`` for the last
        frame that isn't this library's own code or a third-party package."""
        frames = traceback.extract_tb(exception.__traceback__)
        for frame in reversed(frames):
            directory = os.path.dirname(os.path.abspath(frame.filename))
            if directory.startswith(_PACKAGE_DIR):
                continue
            if f"{os.sep}site-packages{os.sep}" in frame.filename:
                continue
            formatted = f"{os.path.basename(frame.filename)}:{frame.lineno} in {frame.name}"
            return formatted, (frame.line or "").strip()
        if frames:
            return frames[-1].name, (frames[-1].line or "").strip()
        return "", ""


class LambdaContext:
    """Minimal stand-in for the AWS Lambda context object."""

    def __init__(self, function_name: str = "local", memory_limit_in_mb: int = 128,
                 timeout_ms: int = 30000):
        self.function_name = function_name
        self.function_version = "$LATEST"
        self.memory_limit_in_mb = memory_limit_in_mb
        self.aws_request_id = f"local-{int(time.time() * 1000)}"
        self.log_group_name = f"/aws/lambda/{function_name}"
        self._deadline = time.time() + timeout_ms / 1000

    def get_remaining_time_in_millis(self) -> int:
        return max(0, int((self._deadline - time.time()) * 1000))


def _guess_service_name(app: Any) -> str:
    if app is None:
        return "service"
    name = getattr(app, "name", None) or getattr(app, "title", None)
    return str(name) if name else "service"


def _exception_status_code(exception: Optional[BaseException]) -> Optional[int]:
    """Read an HTTP status off a custom exception (e.g. ``AuthError.status_code = 401``)."""
    if exception is None:
        return None
    value = getattr(exception, "status_code", None)
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if 100 <= value <= 599 else None


def _shallow(value: Any, limit: int = 500) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, dict):
        return {str(k): _shallow(v, limit) for k, v in list(value.items())[:50]}
    if isinstance(value, (list, tuple, set)):
        return [_shallow(v, limit) for v in list(value)[:50]]
    try:
        return repr(value)[:limit]
    except Exception:
        return "<unrepresentable>"
