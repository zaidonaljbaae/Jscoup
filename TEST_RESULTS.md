# JSCOUP 1.0.0 — Test Results

**Result: 549 passed, 5 skipped, 0 failed** (1 unrelated deprecation warning from a test dependency, not from JSCOUP itself).

```
549 passed, 5 skipped, 1 warning in 311.05s (0:05:11)
```

## How this was run

```
pip install -e ".[dev]"
pytest tests -q
```

- **Date:** 2026-09-24
- **Python:** 3.12.7 (Windows, MSC v.1941 64-bit)
- **Key dependency versions in the test environment:** Flask 3.1.3, FastAPI 0.141.1, Django 6.1.1, SQLAlchemy 2.0.52, cryptography 50.0.1, pymongo 4.18.1, PyYAML 6.0.3, paramiko 5.0.0, pytest 9.1.1
- **Test count:** 554 collected (549 passing, 5 skipped)

## About the 5 skipped tests

The suite marks tests that need a real, reachable Postgres or MongoDB server (not a mock/fake) with `@pytest.mark.real_server`, gated by `JSCOUP_TEST_*` environment variables (see `pyproject.toml`'s `[tool.pytest.ini_options]` markers). These were skipped in this run because no live Postgres/MongoDB service was pointed at via those variables — this is expected for a local run against SQLite-backed defaults, not a defect. The Postgres `summary()` regression test (`test_summary_groups_errors_by_actor_on_real_postgres`, psycopg v3) is one of these; it was also run against a real PostgreSQL 16 server and confirmed to fail on the pre-fix code with `GroupingError`. The project's own CI workflow (`.github/workflows/ci.yml`) runs these against real Postgres and MongoDB service containers.

## What the suite actually covers

- Core capture/diagnosis pipeline (`test_core.py`, `test_analyzers*.py`)
- All four storage backends, including real-server-marked tests for `SqlStorage`/`MongoStorage`
- Flask, FastAPI and Django integration (`test_frameworks.py`) — Django's own tests require the `Django` package, present here
- Gateway open/gated APIs and token forwarding (`test_gateway_open_apis.py`)
- FastAPI route discovery: parameters (required/optional, form vs query vs body, rules and allowed values), token detection through dependency chains (required / optional / none), and the public-through-gateway flag (`test_fastapi_dependency_params.py`)
- Dashboard, sessions, login lockout, and gateway (realm isolation, encrypted downstream credentials, token expiry, IP allow-lists)
- Registry/discovery for both path-parameter conventions (Flask `<converter:name>` vs FastAPI/Starlette `{name:converter}`) and both sync/async replay (`invoke`/`ainvoke`)
- The security-hardening regression suite added for the 2.3.1rc1 → 1.0.0 line (`SECURITY_UPGRADE.md`'s changes): PBKDF2 iteration count, request/response size caps, security headers, Origin/Fetch-Metadata rejection

## Real-world integration checks (beyond the unit suite)

This release was additionally installed and exercised inside two independent real applications, not just its own test suite:

1. **gravdyn_platform** (FastAPI backend + a second FastAPI storage microservice, real Postgres) — both processes booted cleanly with this library installed, dashboards reachable at `/__jscoup` on each service's own port, capturing real request traffic and internal `watch_module`-instrumented service calls.
2. **A ~25-lambda Flask/AWS test project** — the vendored wheel was upgraded to this build, the local runner (`start_local.ps1`) rebuilt its Postgres-backed environment and reported its dashboard ready at `http://127.0.0.1:5000/__jscoup` with no startup errors.

No regressions or crashes were observed in either integration during this pass.
