"""PS clause "container images", end to end: real public images -> VERA's own API -> a validated CycloneDX CBOM.

Images come from Docker Hub via fetch_image.py (digests verified). The scan runs through the product's HTTP API in
this process (FastAPI TestClient) against a scratch database, so nothing touches a running instance. For each image:
the full-scan job with the image as target, the resulting inventory by class, the CBOM export, and the offline
validation against the official CycloneDX schema plus VERA's rules, and element-by-element conformance to CERT-In's
Table 9 (versions, modes and OIDs included).

    python container_e2e.py      -> research/results/container_e2e.json (+ the CBOMs next to it)
"""
from __future__ import annotations

import collections
import json
import os
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
os.environ["VERA_DB_PATH"] = str(Path(tempfile.mkdtemp()) / "container_e2e.db")
os.environ["VERA_AUTH"] = "0"
os.environ["VERA_OFFLINE"] = "1"
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "research" / "experiments"))
os.chdir(ROOT / "backend")

from fastapi.testclient import TestClient  # noqa: E402

from engine.cbom_validate import validate_cbom  # noqa: E402
from engine.certin import conformance  # noqa: E402
from main import app  # noqa: E402
from v1_detector import _commit  # noqa: E402

IMAGES = ("alpine_3.20.oci.tar", "nginx_1.27-alpine.oci.tar")


def main():
    c = TestClient(app)
    out = {"commit": _commit(), "images": {}}
    for name in IMAGES:
        path = HERE / "images" / name
        t = time.perf_counter()
        job = c.post("/api/scan/full", json={"targets": [{"kind": "image", "value": str(path)}], "wait": True}).json()
        seconds = round(time.perf_counter() - t, 2)
        inv = c.get("/api/inventory").json()
        rows = inv.get("rows") or inv.get("items") or []
        cbom = c.get("/api/cbom").json()
        report = validate_cbom(cbom)
        (ROOT / "research" / "results" / f"cbom_{name.replace('.oci.tar', '')}.json").write_text(json.dumps(cbom, indent=1))
        comps = cbom.get("components", [])
        crypto = [x for x in comps if x.get("type") == "cryptographic-asset"]
        cert_in = conformance(cbom)
        elements = {e["element"]: [e["present"], e["applicable"]] for t in cert_in["by_type"] for e in t["elements"]}
        out["images"][name] = {
            "status": job.get("status"), "seconds": seconds, "assets": len(rows),
            "by_class": dict(collections.Counter(r.get("class_label") or r.get("asset_class") for r in rows).most_common()),
            "algorithms": sorted({r.get("algorithm") for r in rows if r.get("algorithm")}),
            "cbom_components": len(comps), "cbom_crypto_assets": len(crypto),
            "cbom_asset_types": dict(collections.Counter(x.get("cryptoProperties", {}).get("assetType") for x in crypto)),
            "cbom_valid": report.get("valid"), "cbom_violations": report.get("violations", report.get("total_violations")),
            "spec": cbom.get("specVersion"),
            "libraries": [[x["name"], x.get("version")] for x in comps if x.get("type") == "library"],
            "certin": {"certin_present": cert_in["present"], "certin_required": cert_in["required"],
                       "certin_percent": cert_in["percent"], "mode_present_applicable": elements.get("Mode"),
                       "oid_present_applicable": elements.get("OID")},
        }
        print(name, json.dumps(out["images"][name])[:700], flush=True)
    (ROOT / "research" / "results" / "container_e2e.json").write_text(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
