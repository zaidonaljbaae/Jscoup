> For the current 2.3.1rc1 security changes and migration requirements, see SECURITY_UPGRADE.md and VALIDATION_231.md. The following text is historical and may describe behavior deliberately changed in this candidate.

# Validation record — 2.3.0

Validation date: 17 September 2026 (2.3.0rc1 baseline); real-database validation and
the two fixes below added the same day. Python 3.12.7, Windows 10 (local run) and
Python 3.12 / Linux (CI matrix also covers 3.9–3.11); Docker Desktop 29.7.2 /
postgres:16-alpine / mongo:7 for the real-server runs below.

## Automated checks

**392 passed, 2 skipped** locally (the 2 skipped are the `real_server`-marked tests,
which need `JSCOUP_TEST_PG_URL`/`JSCOUP_TEST_MONGO_URL` — see below; they run for
real in CI). This includes the 390 tests from the 2.3.0rc1 baseline (344 inherited,
three updated expectations, 41 independent regressions, five delivery/session/sampling
checks) plus 2 new regression tests for this release's fixes. Two inherited SSH tests
still mock Paramiko instead of removed sshtunnel internals; the bind-value privacy
test still requires complete omission of SQL parameters. Independent SSH and
usage-example tests remain updated for the new adapter and the correct JSCoup
constructor.

## Real-database validation (new in 2.3.0)

2.3.0rc1 shipped with `SqlStorage`/`MongoStorage` validated only against SQLite
(through the same SQLAlchemy code path) and `mongomock`, and said so explicitly.
This release closes that gap for Postgres and MongoDB specifically:

**The boot-race fix, reproduced and confirmed against a real server.**
`tests/tools/concurrent_boot.py` spawns 8 separate OS processes (not threads —
this mirrors what gunicorn/uvicorn actually fork) that each construct
`JSCoup(storage=SqlStorage(url, schema=...))` against the same brand-new,
real PostgreSQL 16 database at the same instant:

| | Before the fix | After the fix |
| --- | ---: | ---: |
| Workers that failed to construct | 7 / 8 | 0 / 8 |
| Failure | `psycopg2.errors.UniqueViolation: duplicate key value violates unique constraint "pg_type_typname_nsp_index"` | — |

Run both ways against `postgres:16-alpine` in Docker on 2026-09-17; the "before"
column was captured by temporarily reverting the fix, not simulated. The
`real_server`-marked test in `tests/test_sql_storage.py` runs the same
reproduction (8 threads, throwaway schema, cleaned up after) as part of every
CI run against the real `postgres` service container.

**The Mongo summary rewrite, checked against a real MongoDB, not just mongomock.**
While validating the new `$facet`-based `summary()` (replacing the old
load-everything-into-memory implementation) against `mongomock`, a real divergence
from actual MongoDB was found: `{"actor.subject": {"$ne": None}}` matches a document
where the whole `actor` field is `None`/absent in `mongomock`, but correctly excludes
it in real MongoDB 7 — confirmed by running the identical query against both engines
side by side. The aggregation now uses `{"$type": "string"}` instead, verified
correct against both. The `real_server`-marked test in `tests/test_mongo_storage.py`
runs `summary()` against a real `mongo:7` container in CI, not the mock.

**Not yet validated against a real server:** MySQL, Oracle, SQL Server (the `sql`
extra's other SQLAlchemy dialects — only Postgres and SQLite have real-server
coverage), and a real SSH bastion host (still mocked). Real deployment to AWS
Lambda/Azure Functions/OCI Functions remains untested against a live account, as
2.3.0rc1 already stated — that gap needs real cloud credentials to close, not a
code change, and this release does not claim otherwise.

Real Flask and Django WSGI apps were exercised over localhost HTTP, using SQLite
and Django ORM respectively. Both passed create/read/missing/error, protected
admin access, login, authenticated access, typed-route replay, exception capture
and SQL tracing checks. These are integration fixtures, not customer production
applications. See framework_projects.py and the JSON results. Django replay's
response event_id remained null; successful response and event capture were
verified separately, not reliable replay correlation.

**Independent real-world validation (not part of this library's own test suite):**
three separate, docker-composed demo applications (Flask, Django, FastAPI — a
restaurant API, a hotel API, an Excel-analysis API) were built embedding this
library via `pip install jscoup[<framework>,sql]`, each with its own real Postgres
16 container, each pointing `SqlStorage` at that same Postgres in an isolated
`jscoup` schema. Driven with real HTTP traffic: JSCoup correctly captured and
diagnosed a genuine `ValueError` (bad ISO date string) in the Flask app and a
genuine `psycopg2.errors.ForeignKeyViolation` in the Django app, both straight
from real Postgres, with no test doubles anywhere in the path. This is what
surfaced the boot-race bug fixed in this release (see "Changes since 2.3.0rc1"
above) — found by using the library the way a real integrator would, not by
testing it in isolation. See `demo-projects/README.md` alongside this package.

## Small local throughput experiment

10,000 calls per mode; trivial function; MemoryStorage. One run, no confidence
intervals; rates are descriptive, not capacity commitments. Bare calls do no
capture. Sampling omits approximately 99% of all operations including errors.

| Mode | Producer calls/sec | Background saved | Queue drops |
| --- | ---: | ---: | ---: |
| bare | 28,248,268 | n/a | n/a |
| synchronous | 14,347 | n/a | n/a |
| background | 8,770 | 6580 | 3420 |
| sample_1_percent | 689,294 | 99 | 0 |

Background mode was slower than synchronous capture in this workload and dropped
3,420 events. Its benefit is decoupling storage latency from the request thread,
not necessarily higher CPU throughput. No million-captured-events/sec claim is
supported. No sustained soak, multi-host or resource-exhaustion benchmark was run.
Queue overflow, flush timeout, snapshot isolation, storage failure counters,
realm revocation and generated-credential isolation have deterministic tests.

## Reproduce

From the extracted source directory:

```sh
python -m pip install '.[dev]'
python -m pytest tests -q
PYTHONPATH=. python validation/framework_projects.py flask all
PYTHONPATH=. python validation/framework_projects.py django all
PYTHONPATH=. python validation/benchmark.py
```

To reproduce the real-database validation, start a real Postgres and a real
MongoDB (any host works; below uses throwaway Docker containers) and set the
two env vars before running the `real_server`-marked tests and the standalone
boot-race reproduction:

```sh
docker run -d --rm -p 5440:5432 -e POSTGRES_USER=jscoup -e POSTGRES_PASSWORD=jscoup -e POSTGRES_DB=jscoup postgres:16-alpine
docker run -d --rm -p 27018:27017 mongo:7

export JSCOUP_TEST_PG_URL=postgresql+psycopg2://jscoup:jscoup@localhost:5440/jscoup
export JSCOUP_TEST_MONGO_URL=mongodb://localhost:27018

python -m pytest -q -m real_server           # the two real-server regression tests
python tests/tools/concurrent_boot.py        # 8-process boot race against real Postgres
```

The framework script creates a temporary project with local databases next to
itself. Those runtime databases are excluded from this distribution. The ZIP
contains source, tests, validation scripts/results, release notes and an
installable wheel. No runtime databases, sessions, bytecode caches or generated
application credentials are included.

## Release decision

Suitable for evaluation, controlled staging, and production use of the
Postgres/SQLite/MongoDB storage paths specifically, now that both have real-server
validation and the boot-race defect that would have hit any multi-worker deployment
is fixed and regression-tested in CI. Still not approved by this assessment as a
general "production release" claim covering every documented backend and deployment
target: MySQL/Oracle/SQL Server, a real SSH bastion, and real serverless deployment
(AWS Lambda/Azure Functions/OCI Functions) remain untested against real
infrastructure, and no sustained load/soak test at scale has been run. See
RELEASE_NOTES.md for migration and the remaining, narrowed release gates. Confidence
is high for every tested case (now including two real database engines under real
concurrency), limited for the backends and environments still untested.
