"""Local users, roles and sessions: who may see the inventory and who may change it.

CERT-In's BOM guidelines (v2.0, section 8.4) ask for the inventory to be kept
access-controlled. VERA runs on one machine, often air-gapped, so identity is
local. There is no directory to call and no password leaves the host.

ROLES
-----
Each role is a set of capabilities (CAPABILITIES below), shown as a matrix in Settings, Users and roles.

    viewer    anyone briefed on the estate: reads everything, asks the assistant (read-only turns)
    auditor   CERT-In or internal audit: also reads the agent audit trail
    engineer  the team that owns a system: also creates projects and keeps assistant conversations
    owner     the CII risk owner (CISO): also runs scans of the estate and approves changes
    analyst   the NTRO analyst, the primary user: everything operational (imports, previews, agent actions)
    admin     also changes settings, policy, models and keys, and manages users

PASSWORDS
---------
Passwords are hashed with scrypt (RFC 7914) from the standard library:
N = 2^14, r = 8, p = 1, a 16-byte random salt and a 32-byte key. Comparison is
constant-time. There must be at least 12 characters, with no composition rules
(NIST SP 800-63B, 5.1.1.2).

SESSIONS
--------
A session is a random 256-bit token held in an HttpOnly, SameSite=Strict
cookie. Only its SHA-256 is stored, so a copy of the database cannot be replayed
as a session. Sessions end after 12 hours. Repeated failed sign-ins lock that
username for 5 minutes.

The first admin is created from this machine only (`bootstrap`), or with
`python -m engine.auth add-user NAME --role admin`.

DEMO SIGN-IN
------------
With VERA_DEMO_LOGIN=1 (`run.ps1 -Demo`), the sign-in screen offers "Explore
the demo". It signs in as a built-in `demo` account, an analyst unless
VERA_DEMO_ROLE says otherwise, with no password to type. That account's
password is random and never shown, so the demo button is the only way in.
The button works from this machine only and is off by default: it is for a
synthetic estate on a demo laptop, not for an assessment.
"""

from __future__ import annotations

import argparse
import contextvars
import datetime
import getpass
import hashlib
import hmac
import os
import secrets
import sqlite3
import threading
import time
from pathlib import Path

ROLES = ("viewer", "auditor", "engineer", "owner", "analyst", "admin")
ROLE_INFO = {
    "viewer": ("Viewer", "Anyone briefed on the estate"),
    "auditor": ("Auditor", "CERT-In or internal audit"),
    "engineer": ("Engineer", "The team that owns and fixes a system"),
    "owner": ("Risk owner", "The CII operator's CISO or risk owner"),
    "analyst": ("Analyst", "NTRO analyst: the primary user"),
    "admin": ("Admin", "Runs the V.E.R.A. installation"),
}
# capability -> (what it lets you do, roles that hold it). The API enforces these; Settings shows them as a matrix.
CAPABILITIES = {
    "read": ("See the inventory, risk, plan and evidence; export CBOM, SARIF and PDF; verify signatures",
             set(ROLES)),
    "audit": ("Read the agent audit trail", {"auditor", "owner", "analyst", "admin"}),
    "collaborate": ("Create projects and keep assistant conversations", {"engineer", "owner", "analyst", "admin"}),
    "scan": ("Run scans and imports", {"owner", "analyst", "admin"}),
    "approve": ("Approve agent proposals and migration previews", {"owner", "analyst", "admin"}),
    "operate": ("Everything else operational: previews, discovery, agent actions", {"analyst", "admin"}),
    "admin": ("Change settings, policy, models and keys; manage users", {"admin"}),
}


def can(role: str, capability: str) -> bool:
    return role in CAPABILITIES[capability][1]
MIN_PASSWORD = 12
SESSION_SECONDS = 12 * 3600
LOCK_AFTER, LOCK_WINDOW, LOCK_SECONDS = 5, 600, 300
_SCRYPT = {"n": 2 ** 14, "r": 8, "p": 1, "dklen": 32}
# The signed-in user of the request being served; set by api.auth.AuthMiddleware.
CURRENT_USER: contextvars.ContextVar[dict | None] = contextvars.ContextVar("vera_user", default=None)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username      TEXT PRIMARY KEY,
    display_name  TEXT NOT NULL,
    role          TEXT NOT NULL,
    salt          BLOB NOT NULL,
    password_hash BLOB NOT NULL,
    disabled      INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL,
    last_login    TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
    token_sha256 TEXT PRIMARY KEY,
    username     TEXT NOT NULL,
    created_at   REAL NOT NULL,
    expires_at   REAL NOT NULL
);
"""


class AuthError(Exception):
    """A refusal with a message fit to show the person signing in."""

    def __init__(self, message: str, status: int = 401, retry_after: int | None = None):
        super().__init__(message)
        self.status, self.retry_after = status, retry_after


DEMO_USER = "demo"


def enabled() -> bool:
    """Sign-in is required unless VERA_AUTH is set to 0 (the test suite does)."""
    return os.environ.get("VERA_AUTH", "1").strip().lower() not in {"0", "false", "no", "off"}


def demo_enabled() -> bool:
    """The passwordless demo sign-in: only with VERA_DEMO_LOGIN=1."""
    return os.environ.get("VERA_DEMO_LOGIN", "").strip().lower() in {"1", "true", "yes", "on"}


def demo_role() -> str:
    role = os.environ.get("VERA_DEMO_ROLE", "analyst").strip().lower()
    return role if role in ROLES else "analyst"


def _hash(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, maxmem=64 * 1024 * 1024, **_SCRYPT)


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _check_password(password: str) -> None:
    if len(password or "") < MIN_PASSWORD:
        raise AuthError(f"Use at least {MIN_PASSWORD} characters. A passphrase of several words works well.", 400)


def _check_role(role: str) -> None:
    if role not in ROLES:
        raise AuthError(f"Role must be one of {', '.join(ROLES)}.", 400)


class UserStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._failures: dict[str, list[float]] = {}
        with self._connect() as db:
            db.executescript(_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=10)

    # -- users ---------------------------------------------------------------

    def count(self) -> int:
        """People with accounts. The built-in demo account is not a person and is not counted."""
        with self._connect() as db:
            return db.execute("SELECT COUNT(*) FROM users WHERE username != ?", (DEMO_USER,)).fetchone()[0]

    def demo_user(self) -> dict:
        """The built-in demo account, created on first use with a random password nobody is shown."""
        user = self.get(DEMO_USER)
        role = demo_role()
        if user is None:
            salt = secrets.token_bytes(16)
            with self._lock, self._connect() as db:
                db.execute("INSERT INTO users (username, display_name, role, salt, password_hash, created_at) "
                           "VALUES (?, ?, ?, ?, ?, ?)",
                           (DEMO_USER, "Demo account", role, salt, _hash(secrets.token_urlsafe(32), salt), _now_iso()))
            user = self.get(DEMO_USER)
        elif user["role"] != role:
            with self._lock, self._connect() as db:
                db.execute("UPDATE users SET role = ? WHERE username = ?", (role, DEMO_USER))
            user = self.get(DEMO_USER)
        return user

    def list(self) -> list[dict]:
        with self._connect() as db:
            rows = db.execute("SELECT username, display_name, role, disabled, created_at, last_login "
                              "FROM users ORDER BY username").fetchall()
        return [{"username": r[0], "display_name": r[1], "role": r[2], "disabled": bool(r[3]),
                 "created_at": r[4], "last_login": r[5]} for r in rows]

    def get(self, username: str) -> dict | None:
        return next((u for u in self.list() if u["username"] == username), None)

    def add(self, username: str, password: str, role: str, display_name: str = "") -> dict:
        username = (username or "").strip().lower()
        if not username or not username.replace(".", "").replace("-", "").replace("_", "").isalnum():
            raise AuthError("A username uses letters, digits, '.', '-' or '_'.", 400)
        _check_role(role)
        _check_password(password)
        salt = secrets.token_bytes(16)
        with self._lock, self._connect() as db:
            if db.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
                raise AuthError(f"User {username!r} already exists.", 409)
            db.execute("INSERT INTO users (username, display_name, role, salt, password_hash, created_at) "
                       "VALUES (?, ?, ?, ?, ?, ?)",
                       (username, display_name.strip() or username, role, salt, _hash(password, salt), _now_iso()))
        return self.get(username)

    def update(self, username: str, *, role: str | None = None, disabled: bool | None = None,
               password: str | None = None, display_name: str | None = None) -> dict:
        user = self.get(username)
        if user is None:
            raise AuthError(f"No user {username!r}.", 404)
        if role is not None:
            _check_role(role)
        admins = [u for u in self.list() if u["role"] == "admin" and not u["disabled"]]
        losing_admin = user["role"] == "admin" and not user["disabled"] and (
            (role is not None and role != "admin") or disabled)
        if losing_admin and len(admins) == 1:
            raise AuthError("This is the only active admin. Make another admin first.", 409)
        with self._lock, self._connect() as db:
            if role is not None:
                db.execute("UPDATE users SET role = ? WHERE username = ?", (role, username))
            if display_name is not None:
                db.execute("UPDATE users SET display_name = ? WHERE username = ?", (display_name.strip(), username))
            if disabled is not None:
                db.execute("UPDATE users SET disabled = ? WHERE username = ?", (int(disabled), username))
                if disabled:
                    db.execute("DELETE FROM sessions WHERE username = ?", (username,))
            if password is not None:
                _check_password(password)
                salt = secrets.token_bytes(16)
                db.execute("UPDATE users SET salt = ?, password_hash = ? WHERE username = ?",
                           (salt, _hash(password, salt), username))
                db.execute("DELETE FROM sessions WHERE username = ?", (username,))
        return self.get(username)

    # -- sign-in -------------------------------------------------------------

    def _locked_for(self, username: str, now: float) -> int:
        recent = [t for t in self._failures.get(username, []) if now - t < LOCK_WINDOW]
        self._failures[username] = recent
        if len(recent) >= LOCK_AFTER and now - recent[-1] < LOCK_SECONDS:
            return int(LOCK_SECONDS - (now - recent[-1])) + 1
        return 0

    def verify(self, username: str, password: str) -> dict:
        """The user if the password is right; AuthError otherwise, with the same message for any failure."""
        username = (username or "").strip().lower()
        now = time.time()
        wait = self._locked_for(username, now)
        if wait:
            raise AuthError(f"Too many failed attempts. Try again in {wait} seconds.", 429, retry_after=wait)
        with self._connect() as db:
            row = db.execute("SELECT salt, password_hash, disabled FROM users WHERE username = ?",
                             (username,)).fetchone()
        # Hash even for an unknown user, so timing does not reveal which usernames exist.
        salt, stored, disabled = row if row else (b"\0" * 16, b"", 1)
        ok = hmac.compare_digest(_hash(password or "", salt), stored) and not disabled
        if not ok:
            self._failures.setdefault(username, []).append(now)
            raise AuthError("That username and password do not match an active account.")
        self._failures.pop(username, None)
        with self._connect() as db:
            db.execute("UPDATE users SET last_login = ? WHERE username = ?", (_now_iso(), username))
        return self.get(username)

    def start_session(self, username: str) -> str:
        token = secrets.token_urlsafe(32)
        now = time.time()
        with self._lock, self._connect() as db:
            db.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
            db.execute("INSERT INTO sessions VALUES (?, ?, ?, ?)",
                       (hashlib.sha256(token.encode()).hexdigest(), username, now, now + SESSION_SECONDS))
        return token

    def session_user(self, token: str | None) -> dict | None:
        if not token:
            return None
        with self._connect() as db:
            row = db.execute("SELECT username, expires_at FROM sessions WHERE token_sha256 = ?",
                             (hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
        if not row or row[1] < time.time():
            return None
        user = self.get(row[0])
        return user if user and not user["disabled"] else None

    def end_session(self, token: str | None) -> None:
        if token:
            with self._lock, self._connect() as db:
                db.execute("DELETE FROM sessions WHERE token_sha256 = ?", (hashlib.sha256(token.encode()).hexdigest(),))


_store: UserStore | None = None
_store_lock = threading.Lock()


def store() -> UserStore:
    """The process user store: VERA_AUTH_DB, else backend/data/auth.db next to the scan database."""
    global _store
    with _store_lock:
        if _store is None:
            from store import DB_PATH

            _store = UserStore(os.environ.get("VERA_AUTH_DB") or Path(DB_PATH).with_name("auth.db"))
        return _store


def main(argv: list[str] | None = None) -> int:
    """Create a user or reset a password from the console (the recovery path when no admin can sign in)."""
    parser = argparse.ArgumentParser(prog="python -m engine.auth")
    sub = parser.add_subparsers(dest="command", required=True)
    add = sub.add_parser("add-user")
    add.add_argument("username")
    add.add_argument("--role", choices=ROLES, default="viewer")
    add.add_argument("--name", default="")
    reset = sub.add_parser("reset-password")
    reset.add_argument("username")
    sub.add_parser("list")
    args = parser.parse_args(argv)
    users = store()
    try:
        if args.command == "list":
            for u in users.list():
                print(f"{u['username']:<20} {u['role']:<8} {'disabled' if u['disabled'] else 'active'}")
            return 0
        password = getpass.getpass("Password: ")
        if password != getpass.getpass("Repeat: "):
            print("The two entries differ.")
            return 1
        if args.command == "add-user":
            users.add(args.username, password, args.role, args.name)
        else:
            users.update(args.username, password=password)
    except AuthError as exc:
        print(exc)
        return 1
    print("Done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
