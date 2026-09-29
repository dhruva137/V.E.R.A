"""The /api/v1 integration surface.

This surface carries a write path and is reachable by systems outside this
dashboard, so the tests here are mostly about what it *refuses*. The important
property is not that a tool returns data - that is covered elsewhere - but that
authentication, scope and the agent control plane all still apply when the
caller is somebody else's code.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from engine import agent as agent_module
from engine.api_keys import KeyStore, get_store


@pytest.fixture
def client():
    import main
    return TestClient(main.app)


@pytest.fixture(autouse=True)
def clean_keys():
    """Each test starts with no issued keys.

    The store is a module-level singleton, so without this a key issued by one
    test authenticates a request in another and the auth tests pass for the
    wrong reason.
    """
    store = get_store()
    store._keys.clear()
    yield
    store._keys.clear()


def issue(client, name="test", write=False) -> str:
    response = client.post(
        "/api/access-keys", json={"name": name, "allow_write": write},
    )
    assert response.status_code == 200
    return response.json()["key"]


# --- discovery -----------------------------------------------------------


def test_manifest_is_reachable_without_a_key(client):
    """A caller must be able to learn how to authenticate before it has."""
    response = client.get("/api/v1/manifest")
    assert response.status_code == 200

    body = response.json()
    assert body["name"] == "VERA"
    assert body["tool_count"] == len(agent_module.TOOLS_SCHEMA)
    assert set(body["write_tools"]) == {"migrate_asset", "scan_key_vault"}
    assert "Bearer" in body["auth"]["header"]


def test_manifest_exposes_no_estate_data(client):
    """It is unauthenticated, so it must not leak anything about the estate."""
    body = client.get("/api/v1/manifest").json()
    serialised = str(body).lower()
    for leak in ("tejomaya", "asset_id", "qirs", "total_assets"):
        assert leak not in serialised


# --- authentication ------------------------------------------------------


@pytest.mark.parametrize("path", ["/api/v1/tools", "/api/v1/status"])
def test_endpoints_require_a_key(client, path):
    response = client.get(path)
    assert response.status_code == 401
    assert "www-authenticate" in {h.lower() for h in response.headers}


def test_invoking_a_tool_requires_a_key(client):
    response = client.post("/api/v1/tools/get_estate_summary", json={})
    assert response.status_code == 401


def test_a_garbage_key_is_rejected(client):
    response = client.get(
        "/api/v1/tools", headers={"Authorization": "Bearer vera_sk_not_a_real_key"},
    )
    assert response.status_code == 401


def test_both_header_styles_are_accepted(client):
    """Bearer and X-API-Key are both common enough that supporting one
    guarantees a support conversation on the first integration."""
    key = issue(client)
    assert client.get(
        "/api/v1/tools", headers={"Authorization": f"Bearer {key}"},
    ).status_code == 200
    assert client.get(
        "/api/v1/tools", headers={"X-API-Key": key},
    ).status_code == 200


def test_a_revoked_key_stops_working(client):
    key = issue(client)
    headers = {"Authorization": f"Bearer {key}"}
    assert client.get("/api/v1/tools", headers=headers).status_code == 200

    key_id = client.get("/api/access-keys").json()["keys"][0]["id"]
    assert client.delete(f"/api/access-keys/{key_id}").status_code == 200

    assert client.get("/api/v1/tools", headers=headers).status_code == 401


# --- key handling --------------------------------------------------------


def test_plaintext_is_returned_once_and_never_listed(client):
    """Only a hash is retained, so a listing cannot expose a usable credential."""
    raw = issue(client, name="one-shot")

    listed = client.get("/api/access-keys").json()["keys"]
    assert len(listed) == 1
    entry = listed[0]

    assert "key" not in entry
    assert "digest" not in entry
    assert raw not in str(entry)
    # The hint is enough to tell two keys apart and not enough to use one.
    assert entry["hint"].endswith(raw[-4:])


def test_issued_keys_are_unique():
    store = KeyStore()
    keys = {store.issue(f"k{i}")[1] for i in range(50)}
    assert len(keys) == 50


def test_verify_rejects_empty_input():
    store = KeyStore()
    store.issue("real")
    assert store.verify(None) is None
    assert store.verify("") is None


# --- scope ---------------------------------------------------------------


def test_read_only_key_cannot_reach_the_write_tool(client):
    key = issue(client, write=False)
    response = client.post(
        "/api/v1/tools/migrate_asset",
        json={"asset_id": "anything"},
        headers={"Authorization": f"Bearer {key}"},
    )
    assert response.status_code == 403
    assert "read-only" in response.json()["detail"]


def test_write_key_reaches_the_write_tool(client):
    """Reaching it is not the same as being allowed to apply it - the control
    plane still decides that. This asserts scope, not authorisation."""
    key = issue(client, write=True)
    response = client.post(
        "/api/v1/tools/migrate_asset",
        json={"asset_id": "does-not-exist"},
        headers={"Authorization": f"Bearer {key}"},
    )
    assert response.status_code == 200


def test_tool_listing_reports_what_this_key_may_do(client):
    key = issue(client, write=False)
    tools = client.get(
        "/api/v1/tools", headers={"Authorization": f"Bearer {key}"},
    ).json()["tools"]

    write_tool = next(t for t in tools if t["vera"]["mutating"])
    read_tool = next(t for t in tools if not t["vera"]["mutating"])
    assert write_tool["vera"]["permitted_by_this_key"] is False
    assert read_tool["vera"]["permitted_by_this_key"] is True


# --- invocation ----------------------------------------------------------


def test_unknown_tool_returns_404_naming_the_alternatives(client):
    key = issue(client)
    response = client.post(
        "/api/v1/tools/no_such_tool",
        json={},
        headers={"Authorization": f"Bearer {key}"},
    )
    assert response.status_code == 404
    assert "get_estate_summary" in response.json()["detail"]


def test_tool_schemas_match_the_built_in_agent_exactly(client):
    """One definition, two consumers. If these drift, an external model is being
    told about tools that do not behave the way ours do."""
    from engine.agent import TOOLS_SCHEMA

    key = issue(client)
    exposed = client.get(
        "/api/v1/tools", headers={"Authorization": f"Bearer {key}"},
    ).json()["tools"]

    assert len(exposed) == len(TOOLS_SCHEMA)
    assert (
        {t["function"]["name"] for t in exposed}
        == {t["function"]["name"] for t in TOOLS_SCHEMA}
    )


def test_call_count_increments_per_use(client):
    key = issue(client)
    headers = {"Authorization": f"Bearer {key}"}
    for _ in range(3):
        client.get("/api/v1/status", headers=headers)

    assert client.get("/api/access-keys").json()["keys"][0]["call_count"] >= 3
