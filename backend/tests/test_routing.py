"""Routing tests.

The dashboard is served from the same process as the API, which means a
catch-all route sits behind every API route. That arrangement has one failure
mode worth guarding: the catch-all answering requests the API should have
refused.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from main import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def test_unknown_api_path_is_a_json_404(client):
    """An unknown /api path must not fall through to the app shell.

    It used to: the SPA catch-all returned index.html with 200, so a typo'd
    endpoint surfaced in the browser as "Unexpected token <" from the JSON
    parser, and no API consumer could tell a missing route from a served page.
    """
    for path in ("/api/nonexistent", "/api/typo", "/api/scan/bogus", "/api"):
        response = client.get(path)
        assert response.status_code == 404, f"{path} returned {response.status_code}"
        assert response.headers["content-type"].startswith("application/json"), path


def test_spa_deep_links_still_serve_the_app(client):
    """Everything that is not /api keeps falling back to the app shell."""
    for path in ("/some/deep/link", "/dashboard", "/assets"):
        response = client.get(path)
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/html")


def test_api_routes_are_not_shadowed(client):
    """Route order must keep the real endpoints reachable.

    `/api/assets/{asset_id}` sits between `/api/assets` and
    `/api/assets/{asset_id}/explain`; a path parameter that matched slashes
    would swallow the deeper route.
    """
    client.post("/api/scan/demo")

    assert client.get("/api/health").status_code == 200
    assert client.get("/api/assets").status_code == 200
    assert client.get("/api/cbom").status_code == 200
    # The nested route resolves rather than being eaten by {asset_id}.
    asset_id = client.get("/api/assets").json()[0]["id"]
    assert client.get(f"/api/assets/{asset_id}/explain").status_code == 200


def test_missing_asset_is_a_404_not_a_page(client):
    """A route that exists but has no such record answers for itself."""
    client.post("/api/scan/demo")
    response = client.get("/api/assets/no-such-asset")
    assert response.status_code == 404
    assert response.json()["detail"] == "Asset not found"


def test_path_traversal_cannot_escape_the_static_root(client):
    """The fallback resolves against the static root and refuses to leave it."""
    for path in ("/../main.py", "/../store.py", "/../../etc/passwd"):
        response = client.get(path)
        # Either refused or handed the app shell; never source.
        assert "import " not in response.text
        assert "sqlite3" not in response.text
