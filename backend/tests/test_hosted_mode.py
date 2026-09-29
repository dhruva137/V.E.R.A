"""Hosted mode — the engine on your server, the dashboard on theirs.

The product's value is the engine. Deployed as one container anyone who can
reach the dashboard can call the scoring endpoints directly; hosted mode keeps
the engine behind an issued key so what ships to a customer is a client.

These tests exist because the failure mode is silent in both directions: a
hosted engine that forgets to check is wide open, and a local deployment that
starts checking is bricked for every existing operator.
"""

from __future__ import annotations

import importlib

import pytest
from fastapi.testclient import TestClient


def _app(monkeypatch, hosted: bool):
    """Rebuild the app with the flag set, since middleware reads it at boot."""
    monkeypatch.setenv("VERA_HOSTED_MODE", "1" if hosted else "0")
    import api.security as security
    import main
    importlib.reload(security)
    importlib.reload(main)
    return main.app


def test_local_deployment_is_untouched(monkeypatch):
    """The default must keep working with no key at all — every existing
    single-container and air-gapped install depends on it."""
    client = TestClient(_app(monkeypatch, hosted=False))
    assert client.get("/api/discovery/plugins").status_code == 200


def test_hosted_mode_refuses_an_unkeyed_engine_call(monkeypatch):
    client = TestClient(_app(monkeypatch, hosted=True))
    response = client.get("/api/discovery/plugins")
    assert response.status_code == 401
    body = response.json()
    # A bare 401 leaves an operator debugging the wrong thing.
    assert "hosted mode" in body["error"].lower()
    assert "remedy" in body


def test_hosted_mode_accepts_an_issued_key(monkeypatch):
    app = _app(monkeypatch, hosted=True)
    from engine.api_keys import get_store

    _, raw = get_store().issue("test integration")
    client = TestClient(app)
    response = client.get("/api/discovery/plugins",
                          headers={"Authorization": f"Bearer {raw}"})
    assert response.status_code == 200


def test_hosted_mode_rejects_a_wrong_key(monkeypatch):
    client = TestClient(_app(monkeypatch, hosted=True))
    response = client.get("/api/discovery/plugins",
                          headers={"Authorization": "Bearer not-a-real-key"})
    assert response.status_code == 401


def test_manifest_stays_reachable_so_auth_is_discoverable(monkeypatch):
    """A caller must be able to learn how to authenticate before it can."""
    client = TestClient(_app(monkeypatch, hosted=True))
    assert client.get("/api/v1/manifest").status_code == 200


def test_the_dashboard_itself_is_not_gated(monkeypatch):
    """Serving the client is not privileged; only the engine is."""
    client = TestClient(_app(monkeypatch, hosted=True))
    assert client.get("/").status_code in (200, 404)  # 404 only if static absent


@pytest.fixture(autouse=True)
def _restore(monkeypatch):
    """Leave the app module in its default state for every other test file."""
    yield
    monkeypatch.setenv("VERA_HOSTED_MODE", "0")
    import api.security as security
    import main
    importlib.reload(security)
    importlib.reload(main)
