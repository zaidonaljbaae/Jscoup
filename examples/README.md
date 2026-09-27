# Examples

Each file is a complete, runnable app. Install the extras, run it, then open `/__jscoup`
(login `admin` / `change-me`).

| File | Run with |
|---|---|
| `flask_app.py` | `pip install jscoup[flask]` then `python flask_app.py` (port 5000) |
| `fastapi_app.py` | `pip install jscoup[fastapi] uvicorn python-multipart` then `uvicorn fastapi_app:app --port 8000` |
| `watch_functions.py` | `pip install jscoup` then `python watch_functions.py` (no web framework) |

Every example has a route or function that fails on purpose, so the dashboard has something to show.
