"""WP6: the unified scan job (`/api/scan/full`), its SSE stream and the estate register."""

from __future__ import annotations

import json
import textwrap

import pytest
from fastapi.testclient import TestClient

from engine import estate
from main import app


@pytest.fixture()
def client():
    return TestClient(app)


def _write(root, rel, text):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text).lstrip("\n"), encoding="utf-8")
    return path


@pytest.fixture()
def small_estate(tmp_path):
    _write(tmp_path, "repo/pay/keys.py", """
        from cryptography.hazmat.primitives.asymmetric import rsa
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        """)
    _write(tmp_path, "repo/pay/requirements.txt", "cryptography==41.0.7\nrsa==4.9\n")
    _write(tmp_path, "configs/pay/nginx.conf", """
        server {
            listen 443 ssl;
            server_name pay.demo.example;
            ssl_protocols TLSv1.2 TLSv1.3;
            ssl_ciphers ECDHE+AESGCM:!3DES:!RC4;
        }
        """)
    capture = {"source": "tls", "collected_at": "2026-09-20T10:00:00Z", "findings": [{
        "id": "cap-1", "source_type": "tls", "source_location": "pay.demo.example:443",
        "asset_class": "tls_cipher_suite", "protocol": "TLSv1.0", "cipher_suite": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        "usage": "encryption", "raw_details": {"peer_ip": "203.0.113.10"}}]}
    _write(tmp_path, "captures/tls.json", json.dumps(capture))
    _write(tmp_path, "estate.yaml", """
        name: Test estate
        synthetic: true
        systems:
          - name: payments
            exposure: internal
            criticality: critical
            data_classes: [payment_card]
            hosts: [pay.demo.example:443]
            repo: repo/pay
            configs: [configs/pay]
            captures: [captures/tls.json]
        """)
    return tmp_path


def test_estate_register_expands_to_bound_targets(small_estate):
    targets, declarations, meta = estate.load(small_estate / "estate.yaml")
    assert meta == {"name": "Test estate", "register": str(small_estate / "estate.yaml"), "systems": 1,
                    "synthetic": True, "cost": {}}
    assert [t.kind for t in targets] == ["repo", "path", "capture"]
    config = targets[1]
    assert config.host == "pay.demo.example:443" and config.system == "payments"
    assert declarations[0]["exposure"] == "internal" and declarations[0]["data_classes"] == ["payment_card"]


def test_estate_register_rejects_bad_exposure(tmp_path):
    _write(tmp_path, "e.yaml", "systems:\n  - name: x\n    exposure: dmz\n")
    with pytest.raises(ValueError, match="exposure"):
        estate.load(tmp_path / "e.yaml")


def test_full_scan_runs_every_surface_and_finds_drift(client, small_estate):
    response = client.post("/api/scan/full", json={"estate": str(small_estate / "estate.yaml"), "wait": True})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "done", body
    assert body["result"]["assets"] > 0

    drift = client.get("/api/drift").json()
    rules = sorted(r["rule"] for r in drift["records"])
    assert rules == ["D1", "D2", "D8"]
    assert drift["estate"]["name"] == "Test estate"

    assets = client.get("/api/assets").json()
    systems = {a["raw_details"].get("system") for a in assets}
    assert systems == {"payments"}
    assert any(a["raw_details"].get("drift_ids") for a in assets)
    assert all(a["raw_details"].get("data_classes") == ["payment_card"] for a in assets)


def test_job_events_stream_as_server_sent_events(client, small_estate):
    job = client.post("/api/scan/full", json={"estate": str(small_estate / "estate.yaml"), "wait": True}).json()
    with client.stream("GET", f"/api/scan/jobs/{job['job_id']}/events") as stream:
        text = "".join(stream.iter_text())
    events = [json.loads(line[len("data: "):]) for line in text.splitlines() if line.startswith("data: ")]
    kinds = [e["type"] for e in events]
    assert kinds[0] == "started" and kinds[-1] == "done"
    assert {"collector_started", "collector_finished", "resolved", "drift"} <= set(kinds)
    finished = [e for e in events if e["type"] == "collector_finished"]
    assert {e["collector"] for e in finished} >= {"source", "dependency", "config", "capture"}
    assert [e["seq"] for e in events] == list(range(len(events)))

    status = client.get(f"/api/scan/jobs/{job['job_id']}").json()
    assert status["status"] == "done" and len(status["event_log"]) == len(events)


def test_full_scan_validation(client, tmp_path):
    assert client.post("/api/scan/full", json={}).status_code == 400
    assert client.post("/api/scan/full", json={"targets": [{"kind": "ftp", "value": "x"}]}).status_code == 400
    assert client.post("/api/scan/full", json={"estate": str(tmp_path / "none.yaml")}).status_code == 400
    assert client.get("/api/scan/jobs/nope").status_code == 404


def test_collector_failure_does_not_lose_the_rest(client, tmp_path, monkeypatch):
    from collectors.registry import REGISTRY

    class Broken:
        name, plane, label, description, target_kinds = "binary", "built", "Broken", "raises", ("path",)

        def collect(self, targets, *, limits=None):
            raise RuntimeError("boom")

    monkeypatch.setitem(REGISTRY, "binary", Broken())
    _write(tmp_path, "src/a.py", "import hashlib\nhashlib.md5(b'x')\n")
    body = client.post("/api/scan/full", json={"targets": [{"kind": "path", "value": str(tmp_path / "src")}],
                                               "wait": True}).json()
    assert body["status"] == "done"
    log = client.get(f"/api/scan/jobs/{body['job_id']}").json()["event_log"]
    failed = [e for e in log if e["type"] == "collector_failed"]
    assert failed and failed[0]["collector"] == "binary" and "boom" in failed[0]["error"]
    assert body["result"]["assets"] >= 1


def test_collectors_endpoint_lists_registry_and_grammars(client):
    body = client.get("/api/scan/collectors").json()
    names = {c["name"] for c in body["collectors"]}
    assert {"source", "dependency", "binary", "container", "config", "ssh", "tls", "capture", "vault"} <= names
    assert body["grammars"]["python"] == "tree-sitter"
