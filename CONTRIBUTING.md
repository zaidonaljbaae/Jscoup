# Contributing to JSCoup

Thanks for considering a contribution. This project is maintained by [Zaidon Aljbaae](https://github.com/ZaidonAljbaae).

## Development setup

```bash
git clone https://github.com/zaidonaljbaae/JSCOUP.git
cd jscoup
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # macOS/Linux
pip install -e ".[dev]"
```

`.[dev]` installs every optional extra (Flask, FastAPI, Django, SQLAlchemy, cryptography, pymongo, paramiko, PyYAML) plus `pytest`, so the full suite can run locally.

## Running the tests

```bash
pytest -q
```

Some tests are marked `@pytest.mark.real_server` and need a genuine reachable Postgres/MongoDB (not a mock), gated by `JSCOUP_TEST_PG_URL` / `JSCOUP_TEST_MONGO_URL` environment variables. Without them, those tests are skipped — this is expected for a local run. See `.github/workflows/ci.yml` for how CI provides real service containers for them.

```bash
# Optional, only if you have a local Postgres/MongoDB to test against:
export JSCOUP_TEST_PG_URL=postgresql+psycopg2://user:pass@localhost:5432/jscoup
export JSCOUP_TEST_MONGO_URL=mongodb://localhost:27017
export JSCOUP_REQUIRE_REAL_SERVERS=1   # makes a skip a hard failure instead — use in CI, not casually
pytest -q -m real_server
```

## Before opening a pull request

1. Add or update tests for any behavior change — a bug fix without a regression test can silently regress again.
2. Run the full suite (`pytest -q`) and confirm it's green.
3. Keep the change focused — a bug fix shouldn't also refactor unrelated code.
4. Update `CHANGELOG.md` under an `[Unreleased]` heading if the change is user-visible.
5. If the change touches security-relevant behavior (authentication, session handling, redaction, encryption), call that out explicitly in the PR description — these get closer review.

## Licensing of contributions

By opening a pull request you confirm that:

1. You wrote the contribution, or you have the right to submit it.
2. You license it under the project's [MIT License](LICENSE), and it may be distributed as part of JSCoup, whose copyright holder is Zaidon Aljbaae.
3. You do not add code copied from a project with an incompatible licence.

Sign each commit with `git commit -s` (this adds a `Signed-off-by:` line, the [Developer Certificate of Origin](https://developercertificate.org/)). Pull requests without it will be asked to add it.

## Reporting a bug

Open an issue with:
- JSCoup version (`python -c "import jscoup; print(jscoup.__version__)"`)
- Python version and OS
- The framework you're using it with (Flask/FastAPI/Django/none) and its version
- A minimal reproduction — the smallest snippet that shows the problem

## Reporting a security issue

Please do **not** open a public issue for a security vulnerability — see [SECURITY.md](SECURITY.md) instead.

## Code style

The codebase favors explicit, readable code over cleverness, and comments that explain *why* rather than *what*. No enforced formatter/linter is currently wired into CI — match the style of the surrounding file.
