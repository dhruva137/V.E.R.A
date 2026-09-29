"""Sign-in, roles and the audit trail of both (engine/auth.py, api/auth.py)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api.auth import required_role
from engine import audit_chain, auth
from main import app

ADMIN_PW, ANALYST_PW, VIEWER_PW = "correct horse battery", "analyst passphrase 1", "viewer passphrase 1"


@pytest.fixture
def signed_in(monkeypatch):
    """Sign-in on, with an admin created through bootstrap and one user per other role."""
    monkeypatch.setenv("VERA_AUTH", "1")
    admin = TestClient(app)
    assert admin.get("/api/auth/status").json()["bootstrap_required"] is True
    assert admin.post("/api/auth/bootstrap", json={"username": "Asha", "password": ADMIN_PW}).status_code == 200
    for name, pw, role in (("ravi", ANALYST_PW, "analyst"), ("meera", VIEWER_PW, "viewer")):
        assert admin.post("/api/auth/users", json={"username": name, "password": pw, "role": role}).status_code == 200

    def client_for(name: str, pw: str) -> TestClient:
        c = TestClient(app)
        assert c.post("/api/auth/login", json={"username": name, "password": pw}).status_code == 200
        return c

    return {"admin": admin, "analyst": client_for("ravi", ANALYST_PW), "viewer": client_for("meera", VIEWER_PW)}


def test_policy_table():
    from engine.agent_control import get_control

    assert required_role("GET", "/api/overview") == "read"
    assert required_role("POST", "/api/scan/full") == "scan"
    assert required_role("PUT", "/api/profile") == "admin"
    assert required_role("GET", "/api/access-keys") == "admin"   # keys are not for every reader
    assert required_role("GET", "/api/auth/users") == "admin"
    control = get_control()
    saved = control.settings.mode
    try:
        control.update_settings(mode="read_only")
        assert required_role("POST", "/api/chat") == "read"
        control.update_settings(mode="approval")                   # the agent may now propose changes
        assert required_role("POST", "/api/chat") == "operate"
    finally:
        control.update_settings(mode=saved)


def test_nothing_without_a_session(signed_in):
    anonymous = TestClient(app)
    assert anonymous.get("/api/overview").status_code == 401
    assert anonymous.get("/api/health").status_code == 200
    assert anonymous.post("/api/auth/bootstrap", json={"username": "x", "password": "y" * 12}).status_code == 409


def test_roles_are_enforced(signed_in):
    viewer, analyst, admin = signed_in["viewer"], signed_in["analyst"], signed_in["admin"]
    assert viewer.get("/api/scans").status_code == 200
    assert viewer.post("/api/scan/demo").status_code == 403
    assert analyst.put("/api/profile", json={"profile": "cnsa"}).status_code == 403
    assert admin.put("/api/profile", json={"profile": "commercial"}).status_code == 200
    refused = viewer.post("/api/scan/demo").json()
    assert "Analyst" in refused["detail"] and refused["remedy"]    # names the roles that could do it


def test_passwords_are_scrypt_hashed_and_sign_in_is_audited(signed_in):
    import sqlite3

    with sqlite3.connect(auth.store().path) as db:
        salt, stored = db.execute("SELECT salt, password_hash FROM users WHERE username = 'asha'").fetchone()
    assert ADMIN_PW.encode() not in stored and len(stored) == 32 and len(salt) == 16
    bad = TestClient(app).post("/api/auth/login", json={"username": "ravi", "password": "wrong password here"})
    assert bad.status_code == 401
    actions = [(e["action"], e["actor"]) for e in audit_chain.default().entries(50)]
    assert ("bootstrap_admin", "user:asha") in actions and ("login", "user:ravi") in actions
    assert ("login_failed", "anonymous") in actions
    # A setting changed by a signed-in user is attributed to them, not to "system".
    signed_in["admin"].put("/api/profile", json={"profile": "commercial"})
    assert audit_chain.default().entries(1)[-1]["actor"] == "user:asha"


def test_lockout_after_repeated_failures(signed_in):
    c = TestClient(app)
    for _ in range(auth.LOCK_AFTER):
        c.post("/api/auth/login", json={"username": "meera", "password": "not the password"})
    locked = c.post("/api/auth/login", json={"username": "meera", "password": VIEWER_PW})
    assert locked.status_code == 429 and int(locked.headers["Retry-After"]) > 0


def test_the_last_admin_cannot_be_removed(signed_in):
    admin = signed_in["admin"]
    assert admin.patch("/api/auth/users/asha", json={"role": "viewer"}).status_code == 409
    assert admin.patch("/api/auth/users/ravi", json={"disabled": True}).status_code == 200
    assert signed_in["analyst"].get("/api/scans").status_code == 401  # disabling ends their sessions


def test_cross_site_writes_are_refused(signed_in):
    response = signed_in["analyst"].post("/api/scan/demo", headers={"Origin": "https://evil.example"})
    assert response.status_code == 403 and "another site" in response.json()["detail"]


def test_short_passwords_are_refused(signed_in):
    response = signed_in["admin"].post("/api/auth/users", json={"username": "x", "password": "short"})
    assert response.status_code == 400 and "12" in response.json()["detail"]


def test_demo_sign_in_is_off_unless_turned_on(monkeypatch):
    monkeypatch.setenv("VERA_AUTH", "1")
    client = TestClient(app)
    assert client.get("/api/auth/status").json()["demo"] is False
    assert client.post("/api/auth/demo").status_code == 404


def test_demo_sign_in_is_an_analyst_and_does_not_count_as_an_admin(monkeypatch):
    monkeypatch.setenv("VERA_AUTH", "1")
    monkeypatch.setenv("VERA_DEMO_LOGIN", "1")
    client = TestClient(app)
    status = client.get("/api/auth/status").json()
    assert status["demo"] is True and status["demo_role"] == "analyst"
    user = client.post("/api/auth/demo").json()["user"]
    assert user["username"] == "demo" and user["role"] == "analyst"
    assert client.get("/api/scans").status_code == 200            # signed in
    assert client.put("/api/profile", json={"profile": "cnsa"}).status_code == 403  # settings stay with an admin
    # The demo account is not a person: the first real admin can still be created.
    assert TestClient(app).get("/api/auth/status").json()["bootstrap_required"] is True
    actions = [(e["action"], e["actor"]) for e in audit_chain.default().entries(20)]
    assert ("demo_login", "user:demo") in actions


def test_each_persona_holds_exactly_its_capabilities():
    from engine.auth import can
    # the NTRO analyst runs everything operational; the auditor reads the agent trail but cannot scan
    assert can("analyst", "scan") and can("analyst", "operate") and not can("analyst", "admin")
    assert can("auditor", "audit") and not can("auditor", "scan") and not can("auditor", "collaborate")
    assert can("engineer", "collaborate") and not can("engineer", "scan")
    assert can("owner", "scan") and can("owner", "approve") and not can("owner", "operate")
    assert not can("viewer", "audit") and can("viewer", "read")
    assert required_role("POST", "/api/projects") == "collaborate"
    assert required_role("POST", "/api/projects/p1/scan") == "scan"
    assert required_role("GET", "/api/agent/audit") == "audit"
