"""Sign-in routes and the middleware that enforces roles on every /api call.

The policy is by method first, then by path. It is written out here in full,
so an assessor can read in one place exactly who can do what:

* Reading (GET) needs a viewer. Asking the assistant needs a viewer too, but
  only while the agent is read-only. Once an admin allows it to change things,
  a turn needs an analyst.
* Changing anything (POST, PUT, PATCH, DELETE) needs an analyst.
* Settings, policy, models, keys and users need an admin.

A state-changing request whose Origin header names another site is refused
before any of this runs. The SameSite=Strict cookie already keeps other sites
from riding a session; the Origin check is the second lock on the same door.

With VERA_AUTH=0, sign-in is off and every request acts as the local operator
with the admin role. The test suite runs this way; Settings shows it plainly.
"""

from __future__ import annotations

from ipaddress import ip_address

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from engine import audit_chain, auth

COOKIE = "vera_session"
LOCAL_OPERATOR = {"username": "local", "display_name": "Local operator", "role": "admin", "disabled": False}
CURRENT_USER = auth.CURRENT_USER

# Reachable without a session: health, and what a sign-in screen needs.
OPEN = ("/api/health", "/api/auth/status", "/api/auth/login", "/api/auth/bootstrap", "/api/auth/demo")
# /api/v1 authenticates itself with issued keys (engine/api_keys.py).
SELF_AUTHENTICATED = ("/api/v1/",)
ADMIN = (
    ("PUT", "/api/profile"), ("PUT", "/api/engine/policy"), ("POST", "/api/llm/"), ("DELETE", "/api/llm/"),
    ("POST", "/api/agent/settings"), ("GET", "/api/access-keys"), ("POST", "/api/access-keys"),
    ("DELETE", "/api/access-keys"), ("DELETE", "/api/agent/audit"), ("POST", "/api/packs/"),
    ("POST", "/api/agents/"), ("DELETE", "/api/agents/"), ("POST", "/api/scan/clear"),
    ("*", "/api/auth/users"),
)
# State-changing calls that change nothing: a viewer may make them.
VIEWER_WRITES = ("/api/manifest/verify", "/api/engine/policy/preview", "/api/auth/logout", "/api/auth/password",
                 "/api/cbom/validate")
CHAT = ("/api/chat", "/api/chat/stream")
SCAN = ("/api/scan/", "/api/import", "/api/discovery/", "/api/vault/", "/api/live/")
APPROVE = ("/api/agent/proposals",)
COLLABORATE = ("/api/projects", "/api/threads")
AUDIT_READS = ("/api/agent/audit",)


def required_role(method: str, path: str) -> str:
    """The capability this request needs (engine.auth.CAPABILITIES)."""
    for m, prefix in ADMIN:
        if (m == "*" or m == method) and path.startswith(prefix):
            return "admin"
    if method in ("GET", "HEAD"):
        return "audit" if path.startswith(AUDIT_READS) else "read"
    if path in CHAT:
        from engine.agent_control import get_control

        return "read" if get_control().settings.mode == "read_only" else "operate"
    if path in VIEWER_WRITES:
        return "read"
    if path.startswith(COLLABORATE):
        return "scan" if path.endswith("/scan") else "collaborate"
    if path.startswith(SCAN):
        return "scan"
    if path.startswith(APPROVE):
        return "approve"
    return "operate"


def allowed(user: dict, capability: str) -> bool:
    return user.get("role") in auth.CAPABILITIES[capability][1]


class AuthMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, allowed_origins: list[str]):
        super().__init__(app)
        self.allowed_origins = set(allowed_origins)

    def _same_site(self, request: Request) -> bool:
        origin = request.headers.get("origin")
        if not origin or origin in self.allowed_origins:
            return True
        host = request.headers.get("host", "")
        return origin.split("://", 1)[-1] == host

    async def dispatch(self, request: Request, call_next):
        path, method = request.url.path, request.method
        if not path.startswith("/api") or method == "OPTIONS" or path.startswith(SELF_AUTHENTICATED):
            return await call_next(request)
        if method not in ("GET", "HEAD") and not self._same_site(request):
            return JSONResponse(status_code=403, content={
                "detail": "Refused: this request came from another site.",
                "remedy": "Use VERA from its own address, or add the origin to VERA_ALLOWED_ORIGINS."})
        if not auth.enabled():
            token = CURRENT_USER.set(LOCAL_OPERATOR)
            try:
                return await call_next(request)
            finally:
                CURRENT_USER.reset(token)
        if path in OPEN:
            return await call_next(request)
        user = auth.store().session_user(request.cookies.get(COOKIE))
        if user is None:
            return JSONResponse(status_code=401, content={"detail": "Sign in to continue.", "signed_in": False})
        role = required_role(method, path)
        if not allowed(user, role):
            holders = ", ".join(auth.ROLE_INFO[r][0] for r in auth.ROLES if r in auth.CAPABILITIES[role][1])
            return JSONResponse(status_code=403, content={
                "detail": f"This needs a role that can {auth.CAPABILITIES[role][0].lower()} ({holders}); "
                          f"you are signed in as {auth.ROLE_INFO[user['role']][0]}.",
                "remedy": "Ask an admin to change your role in Settings, Users and roles."})
        token = CURRENT_USER.set(user)
        try:
            return await call_next(request)
        finally:
            CURRENT_USER.reset(token)


def actor() -> str:
    """Who to name in the audit chain for the current request."""
    user = CURRENT_USER.get()
    return f"user:{user['username']}" if user else "system"


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------

router = APIRouter(prefix="/auth")


class Credentials(BaseModel):
    username: str
    password: str


class NewUser(BaseModel):
    username: str
    password: str
    role: str = "viewer"
    display_name: str = ""


class UserChange(BaseModel):
    role: str | None = None
    disabled: bool | None = None
    password: str | None = None
    display_name: str | None = None


class PasswordChange(BaseModel):
    current: str
    new: str


def _raise(exc: auth.AuthError):
    headers = {"Retry-After": str(exc.retry_after)} if exc.retry_after else None
    raise HTTPException(status_code=exc.status, detail=str(exc), headers=headers) from exc


def _set_cookie(response: Response, request: Request, token: str) -> None:
    response.set_cookie(COOKIE, token, max_age=auth.SESSION_SECONDS, httponly=True, samesite="strict",
                        secure=request.url.scheme == "https", path="/api")


def _is_loopback(request: Request) -> bool:
    try:
        return ip_address(request.client.host if request.client else "").is_loopback
    except ValueError:
        return request.client is not None and request.client.host in ("testclient", "localhost")


@router.get("/roles")
def roles_matrix():
    """Who uses V.E.R.A. and what each role may do: one column per role, one row per capability."""
    return {"roles": [{"key": r, "label": auth.ROLE_INFO[r][0], "who": auth.ROLE_INFO[r][1]} for r in auth.ROLES],
            "capabilities": [{"key": k, "label": label, "roles": [r for r in auth.ROLES if r in holders]}
                             for k, (label, holders) in auth.CAPABILITIES.items()]}


@router.get("/status")
def status(request: Request):
    """What the sign-in screen needs: whether sign-in is on, whether an admin must be created, who is signed in."""
    if not auth.enabled():
        return {"auth": False, "bootstrap_required": False, "demo": False, "user": LOCAL_OPERATOR,
                "roles": list(auth.ROLES)}
    users = auth.store()
    return {"auth": True, "bootstrap_required": users.count() == 0,
            "demo": auth.demo_enabled() and _is_loopback(request), "demo_role": auth.demo_role(),
            "user": users.session_user(request.cookies.get(COOKIE)), "roles": list(auth.ROLES)}


@router.post("/demo")
def demo_login(request: Request, response: Response):
    """Sign in as the built-in demo account. Only with VERA_DEMO_LOGIN=1, and only from this machine."""
    if not auth.enabled():
        raise HTTPException(status_code=409, detail="Sign-in is off (VERA_AUTH=0); there is nothing to sign in to.")
    if not auth.demo_enabled():
        raise HTTPException(status_code=404, detail="Demo sign-in is off. Start VERA with run.ps1 -Demo to turn it on.")
    if not _is_loopback(request):
        raise HTTPException(status_code=403, detail="Demo sign-in works only on the machine running VERA.")
    users = auth.store()
    user = users.demo_user()
    audit_chain.append("auth", "demo_login", {"role": user["role"]}, actor=f"user:{user['username']}")
    _set_cookie(response, request, users.start_session(user["username"]))
    return {"user": user}


@router.post("/bootstrap")
def bootstrap(body: NewUser, request: Request, response: Response):
    """Create the first admin. Only while no user exists, and only from this machine."""
    users = auth.store()
    if not auth.enabled():
        raise HTTPException(status_code=409, detail="Sign-in is off (VERA_AUTH=0); there is nothing to set up.")
    if users.count() > 0:
        raise HTTPException(status_code=409, detail="An admin already exists. Sign in instead.")
    if not _is_loopback(request):
        raise HTTPException(status_code=403, detail="The first admin can only be created on the machine running VERA.")
    try:
        user = users.add(body.username, body.password, "admin", body.display_name)
    except auth.AuthError as exc:
        _raise(exc)
    audit_chain.append("auth", "bootstrap_admin", {"username": user["username"]}, actor=f"user:{user['username']}")
    _set_cookie(response, request, users.start_session(user["username"]))
    return {"user": user}


@router.post("/login")
def login(body: Credentials, request: Request, response: Response):
    users = auth.store()
    try:
        user = users.verify(body.username, body.password)
    except auth.AuthError as exc:
        audit_chain.append("auth", "login_failed", {"username": body.username.strip().lower()[:64],
                                                    "reason": "locked" if exc.status == 429 else "mismatch"},
                           actor="anonymous")
        _raise(exc)
    audit_chain.append("auth", "login", {"username": user["username"], "role": user["role"]},
                       actor=f"user:{user['username']}")
    _set_cookie(response, request, users.start_session(user["username"]))
    return {"user": user}


@router.post("/logout")
def logout(request: Request, response: Response):
    if auth.enabled():
        auth.store().end_session(request.cookies.get(COOKIE))
        audit_chain.append("auth", "logout", {}, actor=actor())
    response.delete_cookie(COOKIE, path="/api")
    return {"signed_in": False}


@router.post("/password")
def change_password(body: PasswordChange, request: Request, response: Response):
    user = CURRENT_USER.get()
    if not auth.enabled() or user is None:
        raise HTTPException(status_code=409, detail="Sign-in is off; there is no password to change.")
    users = auth.store()
    try:
        users.verify(user["username"], body.current)
        users.update(user["username"], password=body.new)
    except auth.AuthError as exc:
        _raise(exc)
    audit_chain.append("auth", "password_changed", {"username": user["username"]}, actor=actor())
    _set_cookie(response, request, users.start_session(user["username"]))
    return {"changed": True}


@router.get("/users")
def list_users():
    if not auth.enabled():
        return {"auth": False, "users": [LOCAL_OPERATOR]}
    return {"auth": True, "users": auth.store().list()}


@router.post("/users")
def add_user(body: NewUser):
    try:
        user = auth.store().add(body.username, body.password, body.role, body.display_name)
    except auth.AuthError as exc:
        _raise(exc)
    audit_chain.append("auth", "user_added", {"username": user["username"], "role": user["role"]}, actor=actor())
    return user


@router.patch("/users/{username}")
def change_user(username: str, body: UserChange):
    try:
        user = auth.store().update(username, role=body.role, disabled=body.disabled, password=body.password,
                                   display_name=body.display_name)
    except auth.AuthError as exc:
        _raise(exc)
    changed = sorted(k for k, v in body.model_dump().items() if v is not None)
    audit_chain.append("auth", "user_changed", {"username": username, "fields": changed}, actor=actor())
    return user
