"""Sample 'Tasks' API under test. APP_MODE=vulnerable (default) ships 6 realistic seeded defects;
APP_MODE=fixed has them corrected. The QA suite must catch every defect in vulnerable and pass in fixed."""
from __future__ import annotations
import hashlib, os, time
from collections import defaultdict
from typing import Literal
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, ConfigDict

MODE = os.getenv("APP_MODE", "vulnerable")
FIXED = MODE == "fixed"
app = FastAPI(title="Tasks API", version="1.0.0")

USERS = {"tok-alice": {"id": 1, "name": "alice", "role": "user", "pw_hash": hashlib.sha256(b"alice123").hexdigest()},
         "tok-bob": {"id": 2, "name": "bob", "role": "user", "pw_hash": hashlib.sha256(b"bob123").hexdigest()},
         "tok-admin": {"id": 3, "name": "admin", "role": "admin", "pw_hash": hashlib.sha256(b"admin").hexdigest()}}
TASKS: dict[int, dict] = {}
HITS: dict[str, list[float]] = defaultdict(list)

class TaskIn(BaseModel):
    # strict: schemathesis found {"done": 0} was coerced to False (schema says boolean)
    model_config = ConfigDict(extra="forbid" if FIXED else "allow", strict=FIXED)
    title: str = Field(min_length=1, max_length=200)
    priority: Literal["low", "medium", "high"] = "medium"
    done: bool = False

class TaskOut(BaseModel):
    id: int
    title: str
    priority: Literal["low", "medium", "high"]
    done: bool
    owner_id: int

class UserOut(BaseModel):
    id: int
    name: str
    role: str

def reset():
    TASKS.clear(); HITS.clear()
    TASKS[1] = {"id": 1, "title": "alice private task", "priority": "high", "done": False, "owner_id": 1}
    TASKS[2] = {"id": 2, "title": "bob task", "priority": "low", "done": False, "owner_id": 2}
reset()

def current_user(authorization: str | None = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "missing bearer token")
    tok = authorization.removeprefix("Bearer ")
    if tok in USERS: return USERS[tok]
    # DEFECT 2 (API2 Broken Authentication): any token with known prefix accepted
    if not FIXED and tok.startswith("tok-"): return USERS["tok-alice"]
    raise HTTPException(401, "invalid token")

@app.middleware("http")
async def mw(request: Request, call_next):
    # DEFECT 6 (API4 Unrestricted Resource Consumption): no rate limit in vulnerable mode
    if FIXED and request.url.path.startswith("/tasks"):
        key = request.headers.get("authorization", request.client.host if request.client else "anon")
        now = time.time(); HITS[key] = [t for t in HITS[key] if now - t < 10] + [now]
        if len(HITS[key]) > 50:
            return JSONResponse({"detail": "rate limited"}, status_code=429, headers={"Retry-After": "10"})
    resp: Response = await call_next(request)
    if FIXED:  # DEFECT 5 (API8 Security Misconfiguration): missing security headers
        resp.headers.update({"X-Content-Type-Options": "nosniff", "Cache-Control": "no-store",
                             "Content-Security-Policy": "default-src 'none'", "X-Frame-Options": "DENY"})
    else:
        resp.headers["X-Powered-By"] = "FastAPI/0.1 Python/3.12"
    return resp

from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.routing import Match

@app.exception_handler(StarletteHTTPException)
async def http_exc(request: Request, exc: StarletteHTTPException):
    headers = dict(exc.headers or {})
    if exc.status_code == 405 and FIXED:
        # schemathesis found Allow listed only one method (Starlette registers one route per method)
        methods = set()
        for r in app.router.routes:
            if r.matches({"type": "http", "path": request.url.path, "method": "GET"})[0] != Match.NONE:
                methods |= getattr(r, "methods", set()) or set()
        headers["Allow"] = ", ".join(sorted(methods - {"HEAD"}))
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=headers)

if os.getenv("ALLOW_TEST_RESET") == "1":   # never enable in production
    @app.post("/__test/reset", include_in_schema=False)
    def _reset():
        reset(); return {"reset": True}

@app.get("/health")
def health(): return {"status": "ok"}

@app.get("/me", response_model=UserOut if FIXED else None, responses={200: {"model": UserOut}, 401: {}})
def me(user=Depends(current_user)):
    # DEFECT 3 (API3 Excessive Data Exposure): password hash leaks in vulnerable mode
    return user if not FIXED else {k: user[k] for k in ("id", "name", "role")}

@app.get("/tasks", response_model=list[TaskOut], responses={401: {}, 429: {}})
def list_tasks(user=Depends(current_user)):
    return [t for t in TASKS.values() if t["owner_id"] == user["id"] or user["role"] == "admin"]

@app.post("/tasks", response_model=TaskOut, status_code=201, responses={400: {}, 401: {}, 422: {}, 429: {}})
def create_task(body: TaskIn, user=Depends(current_user)):
    data = body.model_dump()
    tid = max(TASKS, default=0) + 1
    task = {"id": tid, "title": data["title"], "priority": data["priority"], "done": data["done"], "owner_id": user["id"]}
    # DEFECT 4 (API3 Mass Assignment): client-supplied owner_id honoured
    if not FIXED and "owner_id" in data: task["owner_id"] = int(data["owner_id"])
    TASKS[tid] = task
    return task

@app.get("/tasks/{task_id}", response_model=TaskOut, responses={401: {}, 404: {}, 429: {}})
def get_task(task_id: int, user=Depends(current_user)):
    t = TASKS.get(task_id)
    if not t: raise HTTPException(404, "not found")
    # DEFECT 1 (API1 BOLA): no ownership check in vulnerable mode
    if FIXED and t["owner_id"] != user["id"] and user["role"] != "admin":
        raise HTTPException(404, "not found")   # 404 not 403: don't confirm existence
    return t

@app.delete("/tasks/{task_id}", status_code=204, responses={401: {}, 404: {}, 429: {}})
def delete_task(task_id: int, user=Depends(current_user)):
    t = TASKS.get(task_id)
    if not t or (t["owner_id"] != user["id"] and user["role"] != "admin"):
        raise HTTPException(404, "not found")
    del TASKS[task_id]
    return Response(status_code=204)
