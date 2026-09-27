# Integration Guide

How to embed JSCoup into an existing Python project — Flask, FastAPI, Django, or a standalone/serverless function — step by step.

> For the full method-by-method reference, see [API_REFERENCE.md](API_REFERENCE.md). This guide is about *wiring it in*; that one is about *what each function does*.

## Contents

- [1. Install](#1-install)
- [2. The one object you need: `JSCoup`](#2-the-one-object-you-need-jscoup)
- [3. Flask](#3-flask)
- [4. FastAPI / Starlette](#4-fastapi--starlette)
- [5. Django](#5-django)
- [6. Watching non-HTTP code (services, background jobs)](#6-watching-non-http-code-services-background-jobs)
- [7. Serverless (AWS Lambda / Azure Functions / OCI Functions)](#7-serverless-aws-lambda--azure-functions--oci-functions)
- [8. Tracing your database](#8-tracing-your-database)
- [9. Turning on the dashboard login](#9-turning-on-the-dashboard-login)
- [10. Multiple services sharing one dashboard](#10-multiple-services-sharing-one-dashboard)
- [11. A minimal "vendor it inside your own project" pattern](#11-a-minimal-vendor-it-inside-your-own-project-pattern)
- [12. How APIs, parameters and tokens are detected](#12-how-apis-parameters-and-tokens-are-detected)
- [13. Common mistakes](#13-common-mistakes)

## 1. Install

```bash
pip install jscoup                 # core — zero dependencies, SQLite storage
pip install jscoup[flask]          # + Flask adapter
pip install jscoup[fastapi]        # + FastAPI adapter
pip install jscoup[django]         # + Django adapter
pip install jscoup[sql]            # + real SQL storage (Postgres/MySQL/Oracle via SQLAlchemy 2.x)
pip install jscoup[mongo]          # + MongoDB storage
pip install jscoup[crypto]         # + field-level encryption at rest
```

Extras compose: `pip install "jscoup[fastapi,sql,crypto]"`. Requires Python ≥ 3.9.

## 2. The one object you need: `JSCoup`

Everything starts with one instance, conventionally named `bl`:

```python
from jscoup import JSCoup

bl = JSCoup(
    service_name="orders-api",
    dashboard_username="admin",
    dashboard_password="change-me",   # set your own — see §9
)
```

If you skip `dashboard_username`/`dashboard_password`, JSCoup generates a random password and prints it once to your console at startup, rather than leaving the dashboard open with no login at all.

## 3. Flask

```python
from flask import Flask
from jscoup import JSCoup

app = Flask(__name__)

bl = JSCoup(service_name="orders-api", dashboard_username="admin", dashboard_password="change-me")
bl.install(app)          # wraps every route already registered on `app`

if __name__ == "__main__":
    app.run(port=5000)
    # dashboard: http://127.0.0.1:5000/__jscoup
```

Call `bl.install(app)` **after** your blueprints are registered, or call `bl.refresh_targets()` afterward — the dashboard's route list is a snapshot taken at install time, re-scanned automatically before every dashboard request.

## 4. FastAPI / Starlette

```python
from fastapi import FastAPI
from jscoup import JSCoup

app = FastAPI()

bl = JSCoup(service_name="orders-api", dashboard_username="admin", dashboard_password="change-me")
bl.install(app)          # same call — framework is auto-detected from the object

# dashboard: http://127.0.0.1:8000/__jscoup
```

Async routes are captured natively; no extra configuration needed for `async def` endpoints.

## 5. Django

Django has no single "app object" the way Flask/FastAPI do, so wiring is two steps:

```python
# app/monitoring.py
from jscoup import JSCoup

bl = JSCoup(service_name="orders-api", dashboard_username="admin", dashboard_password="change-me")
jscoup_middleware = bl.install_django()   # returns a middleware class
```

```python
# settings.py
MIDDLEWARE = [
    # ... your existing middleware ...
    "app.monitoring.jscoup_middleware",
]
```

The dashboard is then served through Django's own URL dispatcher at `/__jscoup`.

## 6. Watching non-HTTP code (services, background jobs)

A route being captured tells you *an endpoint* failed. `watch`/`watch_module` tell you *which internal function* failed — useful for pure computation, background jobs, or anything not reached directly over HTTP.

**One function:**

```python
@bl.watch(kind="service")
def settle_orders(day: str):
    ...
```

**An entire module, automatically, no per-function decorator:**

```python
import app.services            # import first
bl.watch_module("app.services", recursive=True)   # then wrap — see §12 for why order matters
```

**One class imported from elsewhere** (`watch_module` only wraps classes/functions *defined* in the module you pass it):

```python
from third_party import SomeServiceClass
bl.watch_class(SomeServiceClass)
```

## 7. Serverless (AWS Lambda / Azure Functions / OCI Functions)

```python
from jscoup import JSCoup

bl = JSCoup(service_name="my-function", storage=...)   # see §10 — needs a shared external store

@bl.watch_lambda()
def handler(event, context):
    ...
```

```python
@bl.watch_azure_function()
def main(req):
    ...
```

```python
@bl.watch_oci_function()
def handler(ctx, data=None):
    ...
```

There's no local disk to run a dashboard from *inside* the function itself — point `storage=` at a shared `SqlStorage`/`MongoStorage` and run the dashboard from any other process pointed at the same database (see §10).

## 8. Tracing your database

```python
bl.watch_sqlite()                 # patches the stdlib sqlite3 module globally
```

```python
from sqlalchemy import create_engine
engine = create_engine("postgresql+psycopg://...")
bl.watch_sqlalchemy(engine)       # traces this one Engine's statements
```

Either call attaches every SQL statement's text, bind parameters, duration and call site to whichever request is active when it runs.

## 9. Turning on the dashboard login

```python
bl = JSCoup(
    service_name="orders-api",
    dashboard_username="admin",
    dashboard_password="a-real-secret-from-your-env",   # never hard-code in source control
    dashboard_allowed_ips=["203.0.113.4", "10.0.0.0/8"],  # optional network allow-list
)
```

Pull the password from an environment variable in real deployments:

```python
import os
dashboard_password = os.environ["JSCOUP_DASHBOARD_PASSWORD"]
```

## 10. Multiple services sharing one dashboard

Point every service's `storage=` at the same database (optionally with an isolated schema/prefix so it never collides with your app's own tables):

```python
from jscoup.storage.sql import SqlStorage

storage = SqlStorage("postgresql+psycopg://user:pass@host/db", schema="jscoup")
bl = JSCoup(service_name="orders-api", storage=storage)
```

Any one of the services — or a separate, dedicated process — can then serve the dashboard and it will show events from all of them.

## 11. A minimal "vendor it inside your own project" pattern

If you'd rather not depend on an external PyPI/index install (air-gapped environments, monorepo policies), vendor the library directly inside your project instead of installing it as an external package:

```
your_project/
├── vendor/
│   └── jscoup-1.0.0/        ← copy of this library's `jscoup/` package + pyproject.toml + LICENSE
├── backend/
│   ├── requirements.txt      ← production deps — does NOT list jscoup
│   ├── requirements-dev.txt  ← "-r requirements.txt" + "-e ../vendor/jscoup-1.0.0"
│   └── app/
```

```python
try:
    from jscoup import JSCoup
except ImportError:          # not installed (e.g. production image that excludes requirements-dev.txt)
    JSCoup = None

bl = JSCoup(service_name="my-app") if JSCoup is not None else None

def install_jscoup(app):
    if bl is not None:
        bl.install(app)
```

This keeps JSCoup a genuinely optional, dev-only dependency: your production Docker image (built from `requirements.txt` alone) never even sees it, while local development gets full capture and a dashboard.

## 12. How APIs, parameters and tokens are detected

`bl.install(app)` inspects every route and records, per API: its parameters (required vs optional, where each goes — path / query / form / body — plus defaults, allowed values and rules), and whether it needs a token. For FastAPI this comes from FastAPI's own dependency tree, so `Depends(get_current_user)` (and anything it depends on) is understood, `OAuth2PasswordRequestForm` shows `username` / `password`, and an `OAuth2PasswordBearer(auto_error=False)` shows as *token optional*. You can override the token flag for one route with `endpoint.__jscoup_requires_auth__ = True/False`.

**`grant_type`, `scope`, `client_id`, `client_secret` on a login route.** These are not your app's fields: they are the standard OAuth2 password-form fields that FastAPI's `OAuth2PasswordRequestForm` declares (RFC 6749). The form only *requires* `username` and `password`; the other four are optional and ignored unless your code reads them (`form.scope`, ...). JSCoup lists them because the route accepts them, shows FastAPI's own explanation for each, and tucks them under "optional parameters" on the docs page. If you want a login route that advertises only two fields, declare them yourself (`username: str = Form(...)`, `password: str = Form(...)`) instead of `OAuth2PasswordRequestForm`.

**Open and gated APIs.** By default an API must be marked public (Access tab → Public) to be called through the gateway without a gateway token. Set `gateway_open_tokenless_apis=True` to open every API that needs no token of its own automatically; APIs that do need a token stay gated. On an open API, a bearer token you send is forwarded to the API as its own token. Set `gateway_forward_own_tokens=True` to let an API that *needs* a token be called by presenting that API's own token (for example the one its login route returns): log in, paste the token as the Bearer token on the docs page, and call the protected API — the API itself decides whether to accept it.

**The docs "Run" 401.** Published docs call APIs *through the gateway*. Unless an admin marked the API public (Access tab → Public), the gateway wants a gateway token (from `POST /gw/login`) — even for an API that needs no token of its own, like a login route. The docs page tells you which case you are in.

## 13. Common mistakes

| Mistake | What happens | Fix |
|---|---|---|
| Calling `watch_module("app.services")` **after** another module already did `from app.services import some_function` | The other module's copy of `some_function` is never wrapped — Python bound that name at import time | Call `watch_module` immediately after importing the module, before anything else imports names out of it |
| Expecting `bl.invoke()` to run a plain watched Python function remotely | Refused — only genuine HTTP API targets can be replayed | Use the dashboard/API only for real endpoints; a watched function is *recorded*, not remotely invokable |
| Calling `bl.invoke()` (sync) from inside an already-running async event loop | Deadlocks or raises, depending on context | Use `await bl.ainvoke(...)` instead |
| Assuming the dashboard's call count reflects only *your* manual testing | Every call your own code makes to a watched function counts too | Scope `watch_module`/`watch_class` narrowly if you only want external HTTP traffic counted |
| Leaving `dashboard_username` unset in a shared/deployed environment | A random password is generated and printed to console once — easy to miss in log aggregation | Always pass an explicit `dashboard_password` from an environment variable in anything beyond local dev |
