"""The baseline HTTP hardening is applied to every response.

These lock in the security envelope from api/security.py so a refactor cannot
silently drop a header. They exercise the middleware through the real app.
"""

from fastapi.testclient import TestClient

from main import app


def test_security_headers_present_on_every_response():
    with TestClient(app) as client:
        r = client.get("/api/health")
    assert r.status_code == 200
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["Referrer-Policy"] == "no-referrer"
    assert "default-src 'self'" in r.headers["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]


def test_headers_present_on_error_responses_too():
    """A 404 must be hardened as much as a 200 - error paths are attack paths."""
    with TestClient(app) as client:
        r = client.get("/api/definitely-not-a-route")
    assert r.status_code == 404
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert "Content-Security-Policy" in r.headers


def test_hsts_absent_by_default():
    """HSTS must not be asserted unless explicitly enabled, or a plain-http dev
    host gets pinned to https it cannot serve."""
    with TestClient(app) as client:
        r = client.get("/api/health")
    assert "Strict-Transport-Security" not in r.headers
