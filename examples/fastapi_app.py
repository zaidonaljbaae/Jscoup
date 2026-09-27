"""FastAPI + JSCoup: parameters, required/optional and token needs are detected automatically."""
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from jscoup import JSCoup

app = FastAPI(title="JSCoup FastAPI demo")
oauth2 = OAuth2PasswordBearer(tokenUrl="/login")


def current_user(token: str = Depends(oauth2)):
    if token != "demo-token":
        raise HTTPException(status_code=401, detail="Invalid token")
    return "demo"


@app.post("/login")
def login(form: OAuth2PasswordRequestForm = Depends()):
    """Needs no token. Documented fields: username and password (required)."""
    if (form.username, form.password) != ("demo", "demo"):
        raise HTTPException(status_code=401, detail="Wrong username or password")
    return {"access_token": "demo-token", "token_type": "bearer"}


@app.get("/items")
def items(q: Optional[str] = None, limit: int = 10, user: str = Depends(current_user)):
    """Needs a token (detected from the OAuth2 scheme); q and limit are optional."""
    return {"user": user, "q": q, "limit": limit}


@app.get("/boom")
def boom():
    return 1 / 0  # fails on purpose


bl = JSCoup(service_name="fastapi-demo", dashboard_username="admin", dashboard_password="change-me",
            allow_live_invoke=True, base_url="http://127.0.0.1:8000")
bl.install(app)  # after the routes are registered
