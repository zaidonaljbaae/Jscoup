# API Reference

Every public class and method in JSCoup 1.0.0. For step-by-step wiring instructions, see the [Integration Guide](INTEGRATION_GUIDE.md).

## Contents

- [`JSCoup` — the core class](#jscoup--the-core-class)
- [Configuration fields](#configuration-fields)
- [Analyzers](#analyzers)
- [Storage backends](#storage-backends)
- [Gateway](#gateway)
- [Top-level module exports](#top-level-module-exports)

---

## `JSCoup` — the core class

```python
from jscoup import JSCoup
```

### Constructor

```python
JSCoup(service_name="service", config=None, storage=None, analyzers=None, *, dashboard_password=None, **options)
```

Builds an instance. Every field listed under [Configuration fields](#configuration-fields) is passed as a keyword in `**options`.

### Instrumentation

| Method | Signature | Description |
|---|---|---|
| `watch` | `watch(name=None, kind="service", reraise=True, fallback=None, register=True, tags=None, description="", capture_args=True, healthcheck_allowed=False)` | Decorator: wraps one function or coroutine so every call is captured (parameters, exceptions, duration, result preview). `register=True` also publishes it to the dashboard's Live Tester. |
| `service` | `service(name=None, **kwargs)` | Alias of `watch` with `kind="service"`. |
| `task` | `task(name=None, **kwargs)` | Alias of `watch` with `kind="task"`. |
| `watch_module` | `watch_module(module, kind="service", recursive=False, include=None, exclude=None)` | Wraps every function *and class* defined directly in `module` (object or dotted string). `recursive=True` also walks every submodule of a package. Must run before another module imports names out of `module`. |
| `watch_class` | `watch_class(cls, kind="service", include=None, exclude=None)` | Wraps every plain method defined directly on `cls`. The single-class counterpart of `watch_module`, for classes imported from elsewhere. |
| `watch_sqlite` | `watch_sqlite(global_patch=True)` | Instruments the standard library `sqlite3` module globally. |
| `watch_sqlalchemy` | `watch_sqlalchemy(engine)` | Instruments one specific SQLAlchemy `Engine`. |
| `record_query` | `record_query(sql, params=None, duration_ms=0.0, ...)` | Manually attach a query to the active capture context — for a database driver with no built-in adapter. |

### Framework installation

| Method | Signature | Description |
|---|---|---|
| `install` | `install(app=None, mount_path=None, **kwargs)` | Detects Flask / FastAPI / Starlette / Django from `app` and wires capture middleware + the dashboard mount in one call. |
| `install_django` | `install_django(mount_path=None, **kwargs)` | Explicit Django path — returns a middleware class to add to `MIDDLEWARE` yourself. |
| `refresh_targets` | `refresh_targets() -> int` | Re-scans the installed app's routes right now. Called automatically before every dashboard request; safe to call any time. |

### Serverless

| Method | Signature | Description |
|---|---|---|
| `watch_lambda` | `watch_lambda(name=None)` | Decorator for a real, deployed AWS Lambda `handler(event, context)` — every real invocation is captured. |
| `watch_azure_function` | `watch_azure_function(name=None)` | Same, for an Azure Functions `main(req)` handler. |
| `watch_oci_function` | `watch_oci_function(name=None)` | Same, for an OCI (Oracle Cloud) Functions handler. |
| `simulate_lambda` | `simulate_lambda(handler, name=None)` | Registers a Lambda handler with the dashboard's Live Tester for on-demand invocation, separate from watching real traffic. |

### Replay

| Method | Signature | Description |
|---|---|---|
| `invoke` | `invoke(target_id, params=None, token=None, base_url=None) -> Dict` | Programmatic, synchronous replay of a previously discovered HTTP target. Refuses if called from inside an already-running event loop — use `ainvoke` there instead. |
| `ainvoke` | `await ainvoke(target_id, params=None, token=None, base_url=None) -> Dict` | Async replay — awaits directly on the caller's own event loop, preserving capture context. |
| `register_target` | `register_target(target) -> Target` | Manually register a `Target` the automatic discovery didn't find. |

### Diagnostics & maintenance

| Method | Signature | Description |
|---|---|---|
| `check_apis` | `check_apis(targets=None, timeout=5.0)` | Sweeps every target that opted in with `healthcheck_allowed=True` and reports which respond. |
| `audit_code` | `audit_code(paths=None)` | Static source-code scan (no execution) for common defensive-programming issues. |
| `identify` | `identify(token=None, **fields)` | Manually attach an actor to the active capture context. |
| `note` | `note(message, category="note", level="info", **data)` | Attach a free-form breadcrumb to the active capture context. |
| `metrics` | `metrics() -> dict` | Background-delivery counters: `before_store_failures`, `storage_failures`, publisher accepted/saved/dropped/failed/pending. |
| `flush` | `flush(timeout=5.0) -> bool` | Wait for queued background work. `False` means work remains. |
| `close` | `close(timeout=5.0) -> bool` | Flush and release every open connection. Call during application shutdown. |
| `rotate_dashboard_credentials` | `rotate_dashboard_credentials(password, credential_epoch)` | Change the dashboard password and revoke every existing session at once. |
| `describe` | `describe(...)` | Attach a hand-written description/examples to a registered target, for the published docs view. |

### Class methods (alternate constructors)

| Method | Signature | Description |
|---|---|---|
| `JSCoup.auto` | `auto(app=None, service_name=None, *, dashboard_username=None, dashboard_password=None, **kwargs)` | Build + `watch_sqlite()` + `install(app)` in one call — the fastest path to full coverage. |
| `JSCoup.high_volume` | `high_volume(service_name="service", **options)` | Pre-configured for high-throughput services: background delivery on, success-capture off. |
| `JSCoup.from_config_file` | `from_config_file(app=None, path=None, **overrides)` | Build from a JSON project-config file instead of keyword arguments; auto-generates one on first load. |

---

## Configuration fields

Passed as keyword arguments to `JSCoup(...)`.

### Identity & storage
| Field | Default | Meaning |
|---|---|---|
| `service_name` | `"service"` | Label attached to every captured event. |
| `environment` | `$JSCOUP_ENV` or `"local"` | Free-text environment tag. |
| `db_path` | `.jscoup/events.db` | SQLite file for the default storage backend. |
| `storage` | `SQLiteStorage` | Any `BaseStorage` instance. |
| `max_events` / `retention_days` | `5000` / `14` | Storage caps; oldest rows purged automatically. |

### Dashboard & sessions
| Field | Default | Meaning |
|---|---|---|
| `mount_path` | `/__jscoup` | Where the dashboard/gateway are mounted. |
| `dashboard_enabled` | `True` | Master switch. |
| `dashboard_mount_in_app` | `True` | Mount into the same app/port instead of standalone. |
| `dashboard_username` / `dashboard_password` | `None` | Login credentials (password hashed immediately, PBKDF2-HMAC-SHA256, 600,000 iterations). |
| `dashboard_local_dev` | `False` | Explicit opt-in to run with no login, for throwaway local runs. |
| `dashboard_session_hours` | `12.0` | How long a login session stays valid. |
| `dashboard_login_max_attempts` / `_lockout_seconds` | `5` / `300` | Brute-force lockout, keyed by source+account. |
| `dashboard_allowed_ips` | `None` | IP/CIDR allow-list checked before login runs. |
| `dashboard_max_body_bytes` | `16 MiB` | Hard cap on dashboard request bodies. |
| `trust_proxy_headers` | `False` | Only enable behind a proxy that strips client-supplied forwarding headers itself. |

### Route discovery (what `install(app)` learns about each API)

Each discovered HTTP API becomes a `Target` with these fields (also returned by `GET /__jscoup/api/targets`):

| Field | Meaning |
|---|---|
| `params` | List of `ParamSpec`: `name`, `location` (`path` / `query` / `form` / `body` / `argument`), `type`, `required`, `default`, `description`, `choices` (allowed values), `constraints` (`pattern`, `ge`, `le`, `min_length`...), `example` |
| `requires_auth` | `True` when the API needs a token |
| `auth_optional` | `True` when a token is accepted but not required |
| `auth_scheme` | `bearer`, `basic`, `apikey:<header>`... |
| `public` | (docs data only) `True` when an admin marked the API public through the gateway |

For **FastAPI**, all of this is read from FastAPI's own resolved dependency tree, so it matches what FastAPI itself will accept: inputs declared by `Depends(...)` classes/functions (for example `OAuth2PasswordRequestForm`) are included, and a security scheme anywhere in the dependency chain marks the API as needing a token. Flask and Django use their own detection (see the Integration Guide).

## Gateway
| Field | Default | Meaning |
|---|---|---|
| `gateway_enabled` | `False` | Turns on `POST /gw/login` and per-user scoped proxying. |
| `gateway_db_path` | `.jscoup/gateway.db` | Realm-specific local SQLite file. |
| `gateway_token_ttl_hours` | `1.0` | How long a login-issued token stays valid. |
| `gateway_open_tokenless_apis` | `False` | Treat every API that needs no token of its own as open through the gateway (no gateway token required), as if marked public. APIs that do need a token are never opened by this. |
| `gateway_forward_own_tokens` | `False` | Let a caller reach an API that needs a token by presenting that API's own token (e.g. from its login route) as the Bearer token; the gateway forwards it and the API accepts or rejects it. A valid gateway login token is still treated as a gateway token. |
| `gateway_rate_limit` / `_rate_window` | `120` / `60s` | Requests allowed per token per window. |
| `invoke_max_concurrency` | `8` | Concurrent replay/proxy calls allowed per process. |
| `invoke_max_response_bytes` | `2 MiB` | Replay responses larger than this return an error. |
| `redact_replay_response` | `False` | Mask token/password-like fields in the response that replay, the Live Tester and gateway calls hand back. Off by default (the response is the API's real answer); captured events, call logs and stored previews are always redacted. |

### Capture behaviour
| Field | Default | Meaning |
|---|---|---|
| `enabled` | `True` | Master switch for all capture. |
| `capture_success` | `False` | Also store full detail for successful calls. |
| `capture_slow` / `slow_request_ms` / `slow_query_ms` | `True` / `1000` / `200` | Flag slow requests/queries even when they succeed. |
| `n_plus_one_threshold` | `8` | Queries-per-request above this trips the N+1 detector. |
| `capture_headers` | `True` | Include request headers (after redaction). |
| `capture_print` | `False` | Tee `sys.stdout` and attach printed output to the active event. |
| `sample_rate` | `1.0` | Head sampling — unsampled calls are not recorded at all. |

### Privacy & encryption
| Field | Default | Meaning |
|---|---|---|
| `sensitive_keys` / `mask` | built-in list / `"[redacted]"` | Field names redacted from captured payloads. |
| `encryption_key` | `None` | Fernet key (`jscoup[crypto]`) — field-level encryption at rest. |
| `before_store` | `None` | Callback to inspect/rewrite/suppress an event before persistence. |
| `on_event` | `None` | Callback fired for every fully-stored event. |

---

## Analyzers

`jscoup.analyzers` — a fixed, priority-ordered chain. The first analyzer whose rules match wins:

1. **Database** — missing table/column, unique/FK/NOT NULL/check violations, deadlocks, pool exhaustion, "not found" ORM exceptions.
2. **Data shape** — type mismatches, unexpected `None`, malformed JSON.
3. **Validation** — missing/invalid required fields.
4. **Network** — DNS failures, connection refused/timeouts.
5. **Auth** — missing/expired/invalid tokens, permission decorator rejections.
6. **Access** — 403-shaped authorization failures.
7. **HTTP** — generic 4xx/5xx.
8. **Performance** — slow requests/queries, N+1 patterns.
9. **Config** — missing environment variables, misconfigured connections.
10. **Generic** (fallback) — anything unmatched; still returns the exact source line.

Pass your own via `JSCoup(analyzers=[...])`.

## Storage backends

`jscoup.storage` — all implement the same `BaseStorage` interface.

| Class | Backend | Extra | Use when |
|---|---|---|---|
| `SQLiteStorage` | Local SQLite file | none | Default — single process, no shared infra. |
| `SqlStorage` | Postgres / MySQL / Oracle (SQLAlchemy 2.x) | `jscoup[sql]` | Multiple workers/replicas sharing one dashboard; supports `schema="jscoup"` for table isolation. |
| `MongoStorage` | MongoDB | `jscoup[mongo]` | App already standardizes on MongoDB. |
| `MemoryStorage` | In-process dict | none | Unit tests. |

## Gateway

`jscoup.gateway.GatewayStore` — admin-curated per-user access to the discovered API surface. Key methods: `create_user(username, password, allowed_target_ids, allowed_ips=None)`, `login(username, password, client_ip)`, `revoke(user_id)`, `authenticate(token)`. See the [Integration Guide](INTEGRATION_GUIDE.md) and the White Paper for the full trust model.

## Top-level module exports

```python
from jscoup import (
    JSCoup, JSCoupConfig, LambdaContext,
    EventRecord, QueryRecord, Breadcrumb, Diagnosis, Actor, build_fingerprint,
    BaseStorage, SQLiteStorage, MemoryStorage,
    AnalyzerEngine, BaseAnalyzer, AnalysisInput,
    DatabaseAnalyzer, DataShapeAnalyzer, ValidationAnalyzer, AuthAnalyzer,
    AccessAnalyzer, NetworkAnalyzer, ConfigAnalyzer, HttpAnalyzer,
    PerformanceAnalyzer, GenericAnalyzer,
    connect, emit_query, instrument_sqlite3, uninstrument_sqlite3,
    instrument_sqlalchemy, uninstrument_sqlalchemy, instrument_django,
    IdentityResolver, fingerprint_token, decode_jwt_payload, Redactor, hash_password,
    Registry, Target, ParamSpec, Simulator,
    ConnectivityCheck, check_connectivity, AuditFinding, audit_code,
    ApiCheckResult, check_apis,
    GatewayStore, GatewayUser, ALL_TARGETS,
    EncryptingStorage, generate_encryption_key,
    run_load_test, format_loadtest_report,
    current_context, all_contexts, add_breadcrumb,
    __version__,
)
```
