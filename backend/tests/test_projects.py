"""Projects file their scans and keep the assistant conversations held about them."""

from __future__ import annotations

from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def test_a_project_scans_its_targets_and_files_the_result():
    p = client.post("/api/projects", json={"name": "Milestone-1 inventory", "purpose": "DST foundations",
                                           "sector": "Banking", "estate": "demo"}).json()
    assert p["name"] == "Milestone-1 inventory" and p["targets"][0]["kind"] == "estate"
    job = client.post(f"/api/projects/{p['id']}/scan?wait=true").json()
    assert job["status"] == "done"
    detail = client.get(f"/api/projects/{p['id']}").json()
    assert [s["scan_id"] for s in detail["scans"]] == [job["result"]["scan_id"]]
    assert detail["scans"][0]["assets"] > 0
    listed = {x["id"]: x for x in client.get("/api/projects").json()}
    assert listed[p["id"]]["scans"] == 1


def test_a_project_without_targets_says_what_to_add():
    p = client.post("/api/projects", json={"name": "Empty"}).json()
    r = client.post(f"/api/projects/{p['id']}/scan")
    assert r.status_code == 400 and "no targets" in r.json()["detail"]


def test_assistant_conversations_are_kept_per_project_and_titled_by_the_first_question():
    p = client.post("/api/projects", json={"name": "Vendor appliance"}).json()
    t = client.post("/api/threads", json={"project_id": p["id"], "messages": [
        {"role": "user", "content": "Which assets miss the 2027 milestone?"},
        {"role": "assistant", "content": "Seventeen, led by the root CA."},
        {"role": "tool", "content": "ignored: only the conversation is kept"}]}).json()
    assert t["title"] == "Which assets miss the 2027 milestone?" and len(t["messages"]) == 2
    t2 = client.put(f"/api/threads/{t['id']}", json={"project_id": p["id"], "messages": t["messages"] + [
        {"role": "user", "content": "And the root CA?"}]}).json()
    assert len(t2["messages"]) == 3
    listed = client.get(f"/api/threads?project={p['id']}").json()
    assert [x["id"] for x in listed] == [t["id"]] and listed[0]["message_count"] == 3
    assert client.delete(f"/api/threads/{t['id']}").status_code == 200
    assert client.get(f"/api/threads/{t['id']}").status_code == 404


def test_the_live_detector_finds_siphash_and_leaves_clean_programs_alone():
    r = client.get("/api/detector/live").json()
    by = {p["name"]: p for p in r["programs"]}
    assert by["siphash_x86_64"]["flagged"] and by["siphash_x86_64"]["found_by"] == ["learned_function"]
    assert 0 < by["siphash_x86_64"]["q_value"] <= by["siphash_x86_64"]["alpha"]
    assert not by["lz4_x86_64"]["flagged"] and not by["xxhash_x86_64"]["flagged"]
    assert r["correct"] == r["total"] == 4
