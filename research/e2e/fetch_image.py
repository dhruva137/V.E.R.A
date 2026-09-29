"""Fetch a real public image from Docker Hub as an OCI archive, without a Docker daemon (PS clause: container images).

Uses the registry v2 API with an anonymous pull token, selects the linux/amd64 manifest, downloads config and
layers, verifies every blob's sha256 against its digest, and writes an OCI image-layout tarball that VERA's
container collector reads. Nothing is executed.

    python fetch_image.py library/alpine 3.20   -> research/e2e/images/alpine_3.20.oci.tar
"""
from __future__ import annotations

import hashlib
import io
import json
import sys
import tarfile
import urllib.request
from pathlib import Path

OUT = Path(__file__).resolve().parent / "images"
REG = "https://registry-1.docker.io"
ACCEPT = ", ".join(["application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json",
                    "application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"])


def _get(url: str, token: str, accept: str = ACCEPT) -> tuple[bytes, str]:
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}", "Accept": accept})
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read(), r.headers.get("Content-Type", "")


def fetch(repo: str, tag: str) -> Path:
    tok = json.loads(urllib.request.urlopen(
        f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repo}:pull", timeout=60).read())["token"]
    body, ctype = _get(f"{REG}/v2/{repo}/manifests/{tag}", tok)
    doc = json.loads(body)
    if "manifests" in doc:                                  # index: pick linux/amd64
        ref = next(m for m in doc["manifests"] if m.get("platform", {}).get("os") == "linux"
                   and m["platform"].get("architecture") == "amd64")
        body, ctype = _get(f"{REG}/v2/{repo}/manifests/{ref['digest']}", tok, ref["mediaType"])
        doc = json.loads(body)
    blobs = {"sha256:" + hashlib.sha256(body).hexdigest(): body}
    manifest_digest = next(iter(blobs))
    for d in [doc["config"]] + doc["layers"]:
        data, _ = _get(f"{REG}/v2/{repo}/blobs/{d['digest']}", tok, "*/*")
        got = "sha256:" + hashlib.sha256(data).hexdigest()
        if got != d["digest"]:
            raise SystemExit(f"digest mismatch for {d['digest']}: {got}")
        blobs[got] = data
    index = {"schemaVersion": 2, "manifests": [{"mediaType": ctype.split(";")[0], "digest": manifest_digest, "size": len(body),
                                                "annotations": {"org.opencontainers.image.ref.name": f"{repo}:{tag}"}}]}
    OUT.mkdir(exist_ok=True)
    out = OUT / f"{repo.split('/')[-1]}_{tag}.oci.tar"
    with tarfile.open(out, "w") as tar:
        def add(name, data):
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tar.addfile(ti, io.BytesIO(data))
        add("oci-layout", json.dumps({"imageLayoutVersion": "1.0.0"}).encode())
        add("index.json", json.dumps(index).encode())
        for dig, data in blobs.items():
            add(f"blobs/sha256/{dig.split(':')[1]}", data)
    print(f"{repo}:{tag} -> {out} ({out.stat().st_size / 1e6:.1f} MB, {len(doc['layers'])} layers, manifest {manifest_digest[:19]})")
    return out


if __name__ == "__main__":
    fetch(sys.argv[1], sys.argv[2])
