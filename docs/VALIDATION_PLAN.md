# Validation plan (1.0.0)

JSCoup 1.0.0 is the first version and is in its **validation phase**. The code lives on the `dev` branch. It is merged into `main`, tagged and published to PyPI only when every "must" item below is done.

## Status

| # | Check | Must | Status | How |
|---|---|---|---|---|
| 1 | Full test suite, Python 3.12 (Windows) | yes | Done: 549 passed, 0 failed, 5 skipped | `pytest tests` (see `TEST_RESULTS.md`) |
| 2 | Test matrix on Python 3.9, 3.10, 3.11, 3.12 | yes | Pending: runs on the first push to `dev` | `.github/workflows/ci.yml` |
| 3 | Tests against a real PostgreSQL and a real MongoDB | yes | Pending: runs in CI. The Postgres `summary()` test was also run by hand against PostgreSQL 16 | `pytest -m real_server` |
| 4 | Multi-process boot race against one fresh Postgres | yes | Pending: CI job `multi-worker-boot-race` | `tests/tools/concurrent_boot.py` |
| 5 | Wheel installs in an empty environment with no dependencies | yes | Done (3.12) | fresh venv, `pip install jscoup-1.0.0-py3-none-any.whl` |
| 6 | `twine check` on the wheel and sdist | yes | Done | `python -m twine check dist/*` |
| 7 | Runnable examples (Flask, FastAPI, plain functions) | yes | Done (3.12) | `examples/` |
| 8 | Run inside real applications | yes | Done: a FastAPI + Postgres platform and a large Flask multi-service project | manual |
| 9 | Documentation links, site and PDF | yes | Pending: after the push (GitHub Pages deploys from `main` only) | manual click-through |
| 10 | TestPyPI dry run and install | yes | Pending | `twine upload --repository testpypi dist/*` |
| 11 | Independent security review | no | Not done (internal review only) | external |
| 12 | Sustained-load test on target hardware | no | Not done | see "Limits" in the work paper |

## Exit criteria (merge `dev` into `main`)

1. Every "must" row is Done.
2. CI is green on `dev` for all four Python versions.
3. The maintainer signs off.

Then: merge to `main` (this deploys the website), tag `v1.0.0`, publish a GitHub Release (this builds, signs and uploads the package to PyPI).

## Reporting a validation problem

Open an issue with the version, Python version, framework and a minimal reproduction. Security problems go through `SECURITY.md`, not a public issue.
