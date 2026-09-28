# JSCoup

[![PyPI version](https://img.shields.io/pypi/v/jscoup.svg)](https://pypi.org/project/jscoup/)
[![Python versions](https://img.shields.io/pypi/pyversions/jscoup.svg)](https://pypi.org/project/jscoup/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **Status: alpha.** JSCoup **1.0.0** is the first version. The full test suite and the validation plan are kept on the [`dev` branch](https://github.com/zaidonaljbaae/JSCOUP/tree/dev).

**Capture API bugs, explain them, and re-run them — from one local URL.**

[![How JSCoup works](docs/assets/how-it-works.gif)](https://zaidonaljbaae.github.io/Jscoup/)

▶ [Watch the 38-second video](docs/assets/how-it-works.mp4)

**Work paper with diagrams: <https://zaidonaljbaae.github.io/Jscoup/>**

JSCoup wraps your endpoints, services and background handlers the way
`try/except` does, but instead of a bare traceback it records the *whole* failing
operation: every SQL statement with its parameters and timing, the caller behind
the token, the request payload, the breadcrumbs — and then classifies the failure
and suggests fixes. Stored locally by default (SQLite, no network) — or in
your own Postgres/MySQL/Oracle/SQL Server/MongoDB when you point it there —
and published as a browsable, testable page of your API surface.
Runs anywhere your Python already runs: Flask/FastAPI/Django, a standalone
process, or a real deployed AWS Lambda / Azure Function / OCI Function.

Built by **Zaidon Aljbaae**. MIT licensed. Version **1.0.0** — first stable release, built on a security-hardening pass (realm-isolated gateway state, encrypted downstream credentials, hardened login lockout, HTTP security headers — full detail in [SECURITY_UPGRADE.md](SECURITY_UPGRADE.md)).

```bash
pip install jscoup                # core, zero dependencies
pip install jscoup[fastapi,sql]   # + FastAPI adapter + Postgres/MySQL storage
```

```python
from jscoup import JSCoup

bl = JSCoup(service_name="orders-api", db_path=".jscoup/orders.db")
bl.watch_sqlite()         # trace every sqlite3 statement
bl.install(app)           # Flask, FastAPI or Django

# open http://127.0.0.1:8000/__jscoup
```

## Documentation

| | |
|---|---|
| 🌐 [**Work paper (web)**](https://zaidonaljbaae.github.io/Jscoup/) | The whole library explained with diagrams: architecture, diagnosis, gateway, security |
| 📘 [**Integration Guide**](docs/INTEGRATION_GUIDE.md) | How to embed JSCoup into an existing Flask / FastAPI / Django project, step by step |
| 📗 [**API Reference**](docs/API_REFERENCE.md) | Every public class and method, with signatures and descriptions |
| 📄 [User Manual (PDF)](docs/JSCOUP_Manual.pdf) | The Integration Guide + API Reference + config reference, as one printable document |
| 📰 [Work paper (PDF)](docs/JSCOUP_Whitepaper.pdf) | The same work paper as a printable document |
| 🗺️ [Architecture flowchart](docs/flowchart.png) | How one call flows from capture through diagnosis to the dashboard/docs/gateway |
| 📝 [Changelog](CHANGELOG.md) | What changed, by version |
| 🔒 [Security policy](SECURITY.md) | Supported versions, how to report a vulnerability |
| 🤝 [Contributing](CONTRIBUTING.md) | Dev setup, running the test suite, pull request process |
| 🤖 [llms.txt](llms.txt) | Machine-readable summary for AI coding assistants and search tools |

## Why JSCoup instead of…

| | Hand-written OpenAPI/Swagger doc | A hosted APM/error tracker | JSCoup |
|---|---|---|---|
| Documents your real endpoints | ✅ (until it drifts from the code) | ❌ | ✅ — discovered from the live app, not hand-maintained |
| Lets you *execute* an endpoint from the docs page | ❌ | ❌ | ✅ Live Tester |
| Explains *why* a call failed, not just that it did | ❌ | Partial (raw traceback) | ✅ rule-based diagnosis: category + likely cause + fix |
| Captures the exact SQL that failed | ❌ | Rarely | ✅ statement, parameters, timing, call site |
| Hands external partners scoped, expiring access | ❌ | ❌ | ✅ built-in API Gateway |
| Data stays on your own infrastructure | ✅ | ❌ (SaaS) | ✅ (SQLite/Postgres/MySQL/MongoDB you control) |
| Setup | Manual spec authoring | Agent + dashboard + billing | One `pip install` + one `bl.install(app)` call |

---

## Ownership and license

Copyright (c) 2026 **Zaidon Aljbaae**. JSCoup is released under the [MIT License](LICENSE): you may use, copy, modify and distribute it, provided the copyright notice and license text are kept. Every source file carries an SPDX copyright header, the package exposes `jscoup.__author__` / `__copyright__` / `__license__`, and the [NOTICE](NOTICE) file lists what must be preserved. The name and logo are covered separately by the [trademark notice](TRADEMARK.md). To cite the software, see [CITATION.cff](CITATION.cff).

## Table of contents

1. [What it captures](#1-what-it-captures)
2. [Why it is more than `try/except`](#2-why-it-is-more-than-tryexcept)
3. [Architecture](#3-architecture)
4. [Installing on each framework](#4-installing-on-each-framework)
5. [Watching functions, services and serverless platforms](#5-watching-functions-services-and-serverless-platforms)
6. [The dashboard](#6-the-dashboard)
7. [Configuration](#7-configuration)
8. [Database backends & connectivity](#8-database-backends--connectivity)
9. [Extending](#9-extending)
10. [Programmatic replay (CI, scripts)](#10-programmatic-replay-ci-scripts)
11. [Safety notes](#11-safety-notes)

---

## 1. What it captures

| Layer | Captured |
|---|---|
| HTTP | method, route, path params, query, JSON body, headers (redacted), status code, duration, client IP |
| Caller | token fingerprint (SHA-256, never the raw token), subject/label from a static map, a custom resolver, or unverified JWT claims |
| Database | every statement, its parameters, duration, rowcount, the failing one, and the application line that issued it |
| Failure | exception type/module/message, traceback, culprit frame, stable fingerprint for grouping |
| Trail | breadcrumbs added with `bl.note(...)`, nested service calls linked by `parent_id` |
| Performance | slow calls, slow statements, N+1 patterns — even when nothing raised |

## 2. Why it is more than `try/except`

`try/except` sees the exception. JSCoup sees the *situation* around it:

* **Database-aware diagnosis.** `IntegrityError` becomes *"Duplicate value rejected
  by a unique constraint"* with the exact INSERT, the values, three likely causes
  and three concrete fixes. Driver-agnostic: sqlite3, psycopg/psycopg2, MySQL,
  asyncpg, SQLAlchemy and Django all classify without being installed.
* **Data-mismatch diagnosis.** A `TypeError` on `None` after a SELECT is reported
  as a nullable column reaching code that assumes a value — not as a generic
  traceback.
* **Grouping.** Identical failures share a fingerprint, so the dashboard shows
  *issues* (12 occurrences, 3 callers) instead of 12 identical rows.
* **Replay.** Any endpoint or service can be re-run from the browser with the
  same parameters and a token, and the resulting event is linked back.

## 3. Architecture

```
jscoup/
├── core.py             JSCoup          — the single public class
├── config.py           JSCoupConfig    — every knob, no hard-coded behaviour
├── context.py          CaptureContext   — contextvars stack (nesting-safe, thread-safe)
├── models.py           EventRecord, QueryRecord, Breadcrumb, Actor, Diagnosis
├── identity.py         IdentityResolver — token → actor
├── redaction.py        Redactor         — secrets never reach disk
├── dbwatch.py          sqlite3 / SQLAlchemy / Django statement tracing
├── registry.py         Registry, Target — what can be replayed
├── simulator.py        Simulator        — live invocation of endpoints & services
├── analyzers/
│   ├── base.py         BaseAnalyzer, AnalysisInput   (extension point)
│   ├── database.py     DatabaseAnalyzer  — 16 rule families
│   └── common.py       DataShape, Validation, Auth, Network, Config, Http, Performance, Generic
├── storage/
│   ├── base.py         BaseStorage      (extension point)
│   ├── sqlite.py       SQLiteStorage    — local file, WAL, retention
│   └── memory.py       MemoryStorage    — tests
├── dashboard/
│   ├── api.py          DashboardAPI     — framework-agnostic JSON API
│   └── static/index.html                — single-page UI
└── integrations/
    ├── flask.py        install_flask
    ├── fastapi.py      install_fastapi / JSCoupASGIMiddleware
    └── django.py       JSCoupMiddleware / jscoup_urls
```

Every class is independent and replaceable — see §8.

## 4. Installing on each framework

### Flask

```python
from flask import Flask
from jscoup import JSCoup

app = Flask(__name__)
bl = JSCoup(service_name="shop-flask", db_path=".jscoup/shop.db")
bl.watch_sqlite()
bl.install(app)                       # or: bl.install(app, mount_path="/_debug")
```

### FastAPI

```python
from fastapi import FastAPI
from jscoup import JSCoup

app = FastAPI()
bl = JSCoup(service_name="shop-fastapi")
bl.watch_sqlite()
bl.install(app)                       # adds an ASGI middleware + dashboard router
```

### Django

```python
# settings.py
MIDDLEWARE = ["jscoup.integrations.django.JSCoupMiddleware", ...]

# apps.py / wsgi.py
from jscoup import JSCoup
bl = JSCoup(service_name="shop-django")
bl.install_django()                   # registers the instance and DB tracing

# urls.py
from jscoup.integrations.django import jscoup_urls
urlpatterns += jscoup_urls(bl)
```

### Anything else

`JSCoup` works standalone — no framework required:

```python
with bl.capture(kind="task", name="import-csv") as ctx:
    ctx.set_tag("file", path)
    run_import(path)
```

## 5. Watching functions, services and serverless platforms

```python
@bl.watch(kind="service", description="Recomputes stock from order items")
def reconcile_inventory(dry_run: bool = True) -> dict:
    ...

@bl.watch(kind="service")
async def refresh_cache(scope: str = "all"):    # async is supported
    ...
```

`@bl.watch(register=True)` (the default) records every call of the function —
arguments, duration, errors and SQL — under its name. JSCoup is middleware: it
never runs your functions itself. The **Live tester** replays *HTTP APIs* (with
the token you enter), so a watched function is observed when your own code calls
it, not executed from the dashboard.

Useful options: `reraise=False` + `fallback=...` to swallow the error after
recording it, `capture_args=False` to skip argument capture, `tags={...}` for
custom labels.

### Serverless functions (AWS Lambda, Azure Functions, OCI Functions)

Every real invocation of a deployed function handler is captured automatically
— no per-call decoration inside the handler body needed, just wrap the handler
itself once:

```python
# AWS Lambda — def handler(event, context)
@bl.watch_lambda()
def handler(event, context):
    return {"ok": True, "n": len(event["records"])}

# also testable locally, without a real deployment:
result = bl.simulate_lambda(handler, {"records": [1, 2, 3]})
# {"ok": True, "result": {...}, "event_id": "..."}
```

```python
# Azure Functions — def main(req: func.HttpRequest) -> func.HttpResponse
import azure.functions as func

@bl.watch_azure_function()
def main(req: func.HttpRequest) -> func.HttpResponse:
    name = req.params.get("name", "world")
    return func.HttpResponse(f"Hello, {name}")
```

```python
# OCI (Oracle Cloud) Functions — Fn Project Python FDK
from fdk import response

@bl.watch_oci_function()
def handler(ctx, data=None):
    body = data.getvalue() if data else b"{}"
    return response.Response(ctx, response_data=body, headers={"Content-Type": "application/json"})
```

All three wrappers are **duck-typed**: they read the handler's real
event/request object by attribute (`req.method`, `ctx.Headers()`, ...), so
JSCoup itself never imports `boto3`, `azure-functions` or `fdk` — only your
actual deployment needs those packages installed, not this library.

> **Being honest about what "supports X" means here:** the AWS Lambda, Azure
> Functions and OCI Functions wrappers are built and unit-tested against
> hand-built fakes that mirror each platform's own documented handler shape
> (`azure.functions.HttpRequest`/`HttpResponse`, the `fdk` `(ctx, data)`
> pair). They have not been deployed to a live account on any of the three
> platforms as part of building this library. The shape match is exact per
> each platform's own public API — but "verified against the documented
> interface" and "watched working in a real deployed function" are two
> different claims, and only the first one is made here.

## 6. The dashboard

`http://<host>/__jscoup` (configurable via `mount_path`).

* **Overview** — counters, failures by category, failing endpoints, affected callers.
* **Trace strip** — one hour of activity in 60 buckets; red means failures.
* **Events** — filter by status, category, kind, time window, free text.
* **Event detail** — diagnosis (causes + fixes), SQL trail with the failing
  statement highlighted, parameters, headers, breadcrumbs, traceback, and other
  occurrences of the same fingerprint.
* **Issues** — grouped by fingerprint with occurrence and caller counts.
* **Live tester** — pick an endpoint or a service, fill parameters and a token,
  run it, and jump straight to the event it produced.

JSON API (same paths, machine readable):

```
GET  /__jscoup/api/summary            GET  /__jscoup/api/events?status=error&search=orders
GET  /__jscoup/api/timeline           GET  /__jscoup/api/events/<id>
GET  /__jscoup/api/issues             POST /__jscoup/api/events/<id>/resolve
GET  /__jscoup/api/targets            POST /__jscoup/api/invoke
GET  /__jscoup/api/health             POST /__jscoup/api/purge
```

Protect it in shared environments with `dashboard_token="…"` (sent as
`?token=` or the `X-JSCoup-Token` header) and/or `allow_live_invoke=False`.

## 7. Configuration

```python
from jscoup import JSCoup, JSCoupConfig

config = JSCoupConfig(
    service_name="orders-api",
    environment="staging",
    db_path=".jscoup/orders.db",
    mount_path="/__jscoup",
    dashboard_token=None,          # require a token to open the dashboard
    allow_live_invoke=False,       # off by default; opt in to enable replay from the dashboard

    capture_success=False,         # store successful calls too
    capture_slow=True,
    slow_request_ms=1000,
    slow_query_ms=200,
    n_plus_one_threshold=8,
    capture_4xx=False,
    capture_5xx=True,

    max_events=5000,               # rotation
    retention_days=14,

    store_raw_token=False,         # keep only the fingerprint
    sensitive_keys=["password", "token", "api_key", "iban"],
    ignored_paths=["/health", "/metrics"],
    ignored_exceptions=["NotFound"],

    static_tokens={"demo-token-alice": {"subject": "1", "label": "alice@example.com"}},
    identity_resolver=lambda token: {"subject": lookup(token)},
    before_store=lambda event: event,     # return None to drop the event
    on_event=lambda event: notify(event), # webhook, log, alert…
)
bl = JSCoup(config=config)
```

## 8. Database backends & connectivity

JSCoup's own event storage (where *it* keeps what it captured — separate
from your application's own database) has three backends:

| Backend | Covers | Extra |
|---|---|---|
| `SQLiteStorage` (default) | A local file. Zero dependencies, zero setup. | — |
| `SqlStorage` | Any relational database SQLAlchemy supports: **PostgreSQL, MySQL, Oracle, SQL Server**, and SQLite through the same code path. | `pip install jscoup[sql]` |
| `MongoStorage` | **MongoDB** — a document per event, no second table needed for its queries/breadcrumbs. | `pip install jscoup[mongo]` |

**Does pointing at a real database solve the "serverless disk is ephemeral"
problem?** Yes, for exactly that reason — that's what `SqlStorage`/
`MongoStorage` are for. The default `SQLiteStorage` writes to a local file,
which doesn't persist (or isn't guaranteed to) between separate invocations
of an AWS Lambda / Azure Function / OCI Function. Pointing `storage=` at a
real Postgres, MySQL, Oracle, SQL Server or MongoDB instance instead means
every invocation, in every instance of the function, writes to the same
durable store — which is also what lets **one dashboard show events from
many services/instances at once**, not just the process it's mounted in.

```python
from jscoup import JSCoup
from jscoup.storage.sql import SqlStorage       # PostgreSQL / MySQL / Oracle / SQL Server
from jscoup.storage.mongo import MongoStorage   # MongoDB

# 1) a plain connection URL
storage = SqlStorage("postgresql+psycopg2://app:secret@db.internal:5432/orders")
storage = MongoStorage("mongodb://app:secret@db.internal:27017/")

# 2) discrete parts instead of a hand-built URL (safer once a password can
#    contain '@' or '/' — this goes through SQLAlchemy's own URL builder)
storage = SqlStorage(
    drivername="postgresql+psycopg2", username="app", password="p@ss/word",
    host="db.internal", port=5432, database="orders",
)

# 3) a connection file (.json, .yaml/.yml or .ini) instead of hard-coding
#    credentials — the pattern used by a mounted secrets file in a container
storage = SqlStorage.from_file("/etc/jscoup/database.yaml")
storage = MongoStorage.from_file("/etc/jscoup/mongo.json")

# 4) a database reachable only through an SSH bastion/jump host
storage = SqlStorage(
    drivername="postgresql+psycopg2", database="orders",
    host="10.0.4.12", port=5432, username="app", password="secret",
    ssh_tunnel={
        "ssh_host": "bastion.example.com", "ssh_username": "deploy",
        "ssh_pkey": "/home/deploy/.ssh/id_rsa",
    },
)

bl = JSCoup("orders-api", storage=storage)
```

A `database.yaml` connection file looks like:

```yaml
drivername: postgresql+psycopg2
username: app
password: secret
host: db.internal
port: 5432
database: orders
query:
  sslmode: require
ssh_tunnel:
  ssh_host: bastion.example.com
  ssh_username: deploy
  ssh_pkey: /home/deploy/.ssh/id_rsa
```

An isolated schema (Postgres/MySQL) so JSCoup's tables live apart from your
own, even in the same database: `SqlStorage(url, schema="jscoup")`.
SSL client certificates or any other driver-specific connection option go
through `connect_args={...}`, passed straight to SQLAlchemy's
`create_engine()`. SSH tunneling needs `pip install jscoup[ssh]`; a `.yaml`
connection file needs `pip install jscoup[yaml]` (`.json`/`.ini` need
nothing extra).

**What "all databases" means here, honestly:** any relational database with
a SQLAlchemy dialect (Postgres/MySQL/Oracle/SQL Server/SQLite, and several
more third-party dialects) is covered generically through `SqlStorage` —
that's not a per-database integration, it's SQLAlchemy Core's own job.
MongoDB is covered by a dedicated `MongoStorage`, since a document store's
query/aggregation model is different enough from SQL that it needs its own
backend rather than fitting the SQLAlchemy path. Another NoSQL engine
(Redis, DynamoDB, Cassandra, ...) is not covered by either today; implementing
`jscoup.storage.base.BaseStorage`'s ten methods against one is the same
amount of work `MongoStorage` itself took — see [`storage/base.py`](jscoup/storage/base.py)
for the exact contract.

## 9. Extending

**A custom analyzer** — the whole point of the analyzer contract:

```python
from jscoup import BaseAnalyzer, AnalysisInput

class RedisAnalyzer(BaseAnalyzer):
    name = "redis"
    priority = 5                       # runs before the built-ins

    def analyze(self, data: AnalysisInput):
        if "redis" not in data.error_module:
            return None
        return self.verdict(
            category="cache",
            subtype="redis_unavailable",
            title="Redis is unreachable",
            summary="The cache client could not reach the server.",
            likely_causes=["Container not started", "Wrong REDIS_URL"],
            suggested_fixes=["Fall back to the database and answer 200"],
            severity="critical",
            confidence=0.9,
        )

bl.analyzers.register(RedisAnalyzer())
```

**A custom storage backend** — implement `BaseStorage` (Postgres, S3, an HTTP
collector) and pass `JSCoup(storage=MyStorage())`.

**Another driver** — call `bl.record_query(sql, params, duration_ms, error=...)`
from your own wrapper and every analyzer keeps working.

**Renaming** — `JSCoup`, `watch`, `capture`, `install` are plain names in
`jscoup/core.py`; aliasing them (`Tracer = JSCoup`) or renaming them project-wide
breaks nothing else, because no string in the library refers to them.

## 10. Programmatic replay (CI, scripts)

```python
result = bl.invoke(
    "http:POST:/api/users",
    params={"email": "a@b.c", "name": "A"},
    token="demo-token-alice",
    base_url="http://127.0.0.1:5000",
)
assert result["ok"], result["response"]
event = bl.storage.get(result["event_id"])
print(event.diagnosis.title)
```

`bl.registry.to_list()` returns every target with its parameter specs, so a test
suite can iterate over the whole surface automatically.

## 11. Safety notes

* By default (no `storage=` passed), storage is a local SQLite file and
  nothing leaves the machine. Passing a `SqlStorage` (Postgres/MySQL/etc, see
  `jscoup.storage.sql`) is opt-in and, by design, sends captured data to
  wherever that database lives — that's the trade-off of sharing one
  observability store across several services.
* Raw tokens are never stored unless `store_raw_token=True`; the fingerprint is
  a SHA-256 prefix that still lets you group by caller.
* Keys matching `sensitive_keys` are masked in params, headers, query
  strings, tags, breadcrumbs, request/response bodies, and named SQL
  parameters; JWTs and card-like numbers are masked by pattern inside free
  text. This is best-effort pattern/key-based redaction, not a guarantee —
  a secret embedded somewhere this doesn't look (e.g. inside a positional,
  un-named SQL parameter) can still reach storage; review `sensitive_keys`
  for your own domain's field names.
* Capture never breaks the host application: every internal step is guarded, and
  an analyzer that raises is skipped. A hook that itself fails
  (`before_store`) drops the event rather than falling back to storing it
  unsanitized.
* The dashboard requires a login by default: if you don't configure
  `dashboard_username`/`dashboard_password` (or the legacy `dashboard_token`)
  yourself, JSCoup generates and prints an `admin` password for you on
  first run rather than leaving the dashboard open. Pass
  `dashboard_local_dev=True` to explicitly opt back into no-auth for a
  throwaway local run. It's still meant for development and internal
  environments — put it behind your own network controls for anything
  public-facing, and set `dashboard_allowed_ips` (with `trust_proxy_headers`
  only if a proxy you control genuinely overwrites, not appends to,
  `X-Forwarded-For`) to restrict it further.
* `encryption_key` (the `crypto` extra) encrypts specific fields
  (body/response previews, headers, params) before they're written —
  field-level, not whole-file disk encryption. A field that fails to
  encrypt or decrypt is replaced with a placeholder, never silently stored
  or returned in plaintext.
* Live invocation (`allow_live_invoke`, replaying an HTTP target on demand
  from the dashboard; JSCoup never executes Python functions itself) is off by default
  and, when enabled, only ever replays against `base_url` or an explicit
  `allowed_base_urls` entry — a caller can't point it at an arbitrary
  destination.
