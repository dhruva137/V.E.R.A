"""WP3: container collector over synthetic OCI and docker-save images built in-test.

The fixture is a two-layer image: a Debian-like base (OpenSSL 3.0.11 in dpkg and
as a library, a CA bundle, openssl.cnf, sshd_config, a stale private key and a
stale corporate root) and an app layer that whites out the stale key, makes the
local-CA directory opaque, adds a new corporate root, a requirements file and a
signing key baked into the image.
"""

from __future__ import annotations

import datetime
import gzip
import hashlib
import io
import json
import tarfile
from pathlib import Path

import pytest

from collectors.container_scanner import ContainerCollector, classify_path, merged_view, open_image
from collectors.base import CollectResult
from collectors.registry import REGISTRY


# --------------------------------------------------------------------------
# Image builders
# --------------------------------------------------------------------------


def _cert(common_name: str, *, ec: bool = False, ca: bool = True) -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec as ecmod, rsa
    from cryptography.x509.oid import NameOID

    key = ecmod.generate_private_key(ecmod.SECP384R1()) if ec else rsa.generate_private_key(65537, 2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(abs(hash(common_name)) % 10**9 + 1).not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM)


def _elf_with(text: bytes) -> bytes:
    data = bytearray(b"\x7fELF" + b"\x00" * 8188)
    data[2048:2048 + len(text)] = text
    return bytes(data)


def _tar(files: dict[str, bytes], gz: bool) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size, info.mtime = len(data), 0
            tar.addfile(info, io.BytesIO(data))
    raw = buf.getvalue()
    return gzip.compress(raw, mtime=0) if gz else raw


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def build_oci(path: Path, layers: list[dict[str, bytes]], ref: str = "payments-api:1.4") -> Path:
    blobs: dict[str, bytes] = {}
    descs, diff_ids = [], []
    for files in layers:
        raw = _tar(files, gz=False)
        blob = gzip.compress(raw, mtime=0)
        blobs[_digest(blob)] = blob
        diff_ids.append(_digest(raw))
        descs.append({"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                      "digest": _digest(blob), "size": len(blob)})
    config = json.dumps({"architecture": "amd64", "os": "linux", "config": {"Labels": {"team": "payments"}},
                         "rootfs": {"type": "layers", "diff_ids": diff_ids}}).encode()
    blobs[_digest(config)] = config
    manifest = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                           "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                                      "digest": _digest(config), "size": len(config)},
                           "layers": descs}).encode()
    blobs[_digest(manifest)] = manifest
    index = json.dumps({"schemaVersion": 2, "manifests": [{
        "mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": _digest(manifest),
        "size": len(manifest), "annotations": {"org.opencontainers.image.ref.name": ref}}]}).encode()
    files = {"oci-layout": b'{"imageLayoutVersion": "1.0.0"}', "index.json": index}
    files.update({f"blobs/sha256/{d.split(':')[1]}": b for d, b in blobs.items()})
    path.write_bytes(_tar(files, gz=False))
    return path


def build_docker_save(path: Path, layers: list[dict[str, bytes]], tag: str = "payments-api:1.4") -> Path:
    files: dict[str, bytes] = {}
    diff_ids, names = [], []
    for i, layer in enumerate(layers):
        raw = _tar(layer, gz=False)
        files[f"layer{i}/layer.tar"] = raw
        names.append(f"layer{i}/layer.tar")
        diff_ids.append(_digest(raw))
    config = json.dumps({"rootfs": {"type": "layers", "diff_ids": diff_ids}}).encode()
    files["config.json"] = config
    files["manifest.json"] = json.dumps([{"Config": "config.json", "RepoTags": [tag], "Layers": names}]).encode()
    path.write_bytes(_tar(files, gz=False))
    return path


@pytest.fixture(scope="module")
def layers():
    bundle = _cert("Root A") + _cert("Root B") + _cert("Root C", ec=True)
    base = {
        "etc/ssl/certs/ca-certificates.crt": bundle,
        "etc/ssl/openssl.cnf": b"[system_default_sect]\nMinProtocol = TLSv1.2\nCipherString = DEFAULT@SECLEVEL=2\n",
        "etc/ssh/sshd_config": b"KexAlgorithms curve25519-sha256,diffie-hellman-group14-sha256\n",
        "var/lib/dpkg/status": (b"Package: libssl3\nStatus: install ok installed\nVersion: 3.0.11-1~deb12u2\n\n"
                                b"Package: zlib1g\nStatus: install ok installed\nVersion: 1:1.2.13.dfsg-1\n"),
        "usr/lib/x86_64-linux-gnu/libssl.so.3": _elf_with(b"OpenSSL 3.0.11 19 Sep 2023"),
        "usr/share/ca-certificates/mozilla/Root_A.crt": _cert("Root A distro copy"),
        "etc/ssl/private/old.key": b"-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n",
        "usr/local/share/ca-certificates/old-corp.crt": _cert("Old Corp Root"),
    }
    app = {
        "etc/ssl/private/.wh.old.key": b"",
        "usr/local/share/ca-certificates/.wh..wh..opq": b"",
        "usr/local/share/ca-certificates/corp-root.crt": _cert("Corp Root 2026"),
        "app/requirements.txt": b"cryptography==41.0.7\npyjwt==2.8.0\nflask==3.0.0\n",
        "app/config/signing.key": b"-----BEGIN EC PRIVATE KEY-----\nBBBB\n-----END EC PRIVATE KEY-----\n",
    }
    return [base, app]


@pytest.fixture(scope="module")
def oci_image(tmp_path_factory, layers):
    return build_oci(tmp_path_factory.mktemp("oci") / "payments-api.oci.tar", layers)


@pytest.fixture(scope="module")
def base_image(tmp_path_factory, layers):
    return build_oci(tmp_path_factory.mktemp("base") / "debian-base.oci.tar", layers[:1], ref="debian:12")


def _scan(target: str):
    result = ContainerCollector().collect([target])
    return result, result.findings


def _find(findings, **match):
    return [f for f in findings if all(
        (getattr(f, k) if k in type(f).model_fields else f.raw_details.get(k)) == v for k, v in match.items())]


# --------------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------------


def test_oci_image_opens_with_two_layers(oci_image):
    source = open_image(oci_image)
    assert source.kind == "oci"
    assert source.name == "payments-api:1.4"
    assert source.digest.startswith("sha256:")
    assert len(source.layers) == 2


def test_whiteout_and_opaque_directory_are_honoured(oci_image):
    result = CollectResult()
    view = merged_view(open_image(oci_image), result)
    assert "etc/ssl/private/old.key" not in view
    assert "usr/local/share/ca-certificates/old-corp.crt" not in view
    assert "usr/local/share/ca-certificates/corp-root.crt" in view
    assert result.stats["whiteouts"] == 2


def test_findings_from_every_surface(oci_image):
    result, findings = _scan(f"{oci_image}#base_layers=1")
    assert not [f for f in result.failures if "not read" in f["reason"]], result.failures
    trust = _find(findings, asset_class="trust_store")
    assert len(trust) == 1 and trust[0].raw_details["roots"] == 3
    assert sum(trust[0].raw_details["by_algorithm"].values()) == 3

    dpkg = _find(findings, library_id="openssl", ecosystem="deb")
    assert dpkg and dpkg[0].raw_details["library_version"] == "3.0.11"
    assert dpkg[0].raw_details["pqc_capable"] is False

    lib = [f for f in findings if f.raw_details.get("library_id") == "openssl"
           and f.raw_details.get("inner_collector") == "binary_scanner"]
    assert lib and lib[0].raw_details["library_version"] == "3.0.11"

    assert _find(findings, package="cryptography", ecosystem="pypi")
    assert _find(findings, source_type="container", asset_class="config")
    corp = [f for f in findings if f.cert_subject == "CN=Corp Root 2026"]
    assert corp and corp[0].asset_class == "root_ca"


def test_deleted_files_produce_no_findings(oci_image):
    _, findings = _scan(str(oci_image))
    subjects = {f.cert_subject for f in findings if f.cert_subject}
    assert "CN=Old Corp Root" not in subjects
    assert "CN=Root A distro copy" not in subjects  # distro roots are covered by the bundle
    keys = _find(findings, asset_class="embedded_private_key")
    assert [k.raw_details["path_in_image"] for k in keys] == ["/app/config/signing.key"]


def test_layer_origin_from_declared_base_count(oci_image):
    _, findings = _scan(f"{oci_image}#base_layers=1")
    origin = {f.raw_details["path_in_image"]: f.raw_details["layer_origin"] for f in findings}
    assert origin["/var/lib/dpkg/status"] == "base"
    assert origin["/usr/lib/x86_64-linux-gnu/libssl.so.3"] == "base"
    assert origin["/app/requirements.txt"] == "app"
    assert origin["/app/config/signing.key"] == "app"


def test_layer_origin_from_declared_base_image(oci_image, base_image):
    _, findings = _scan(f"{oci_image}#base={base_image}")
    by_path = {f.raw_details["path_in_image"]: f.raw_details for f in findings}
    assert by_path["/etc/ssl/certs/ca-certificates.crt"]["layer_origin"] == "base"
    assert by_path["/app/requirements.txt"]["layer_origin"] == "app"
    assert by_path["/app/requirements.txt"]["layer_digest"] != by_path["/var/lib/dpkg/status"]["layer_digest"]


def test_layer_origin_unknown_without_a_declared_base(oci_image):
    _, findings = _scan(str(oci_image))
    assert {f.raw_details["layer_origin"] for f in findings} == {"unknown"}
    assert all(f.raw_details["base_note"].startswith("no base image") for f in findings)


def test_every_finding_carries_image_provenance(oci_image):
    _, findings = _scan(f"{oci_image}#base_layers=1")
    assert findings
    for f in findings:
        d = f.raw_details
        assert f.source_type == "container"
        assert d["image_digest"].startswith("sha256:") and d["layer_digest"].startswith("sha256:")
        assert d["path_in_image"].startswith("/")
        assert d["discovered_by"].startswith("container_scanner/")
        assert d["evidence_refs"][0]["collector"] == "container_scanner"


def test_findings_keep_the_plane_of_the_inner_collector(oci_image):
    from engine.core.corroboration import plane_for

    _, findings = _scan(str(oci_image))
    planes = {plane_for(f.raw_details["discovered_by"], f.source_type) for f in findings}
    assert {"declared", "built", "held"} <= planes


def test_docker_save_format(tmp_path, layers):
    image = build_docker_save(tmp_path / "payments.tar", layers)
    _, findings = _scan(f"{image}#base_layers=1")
    assert _find(findings, asset_class="trust_store")
    assert all(f.raw_details["layer_digest"].startswith("sha256:") for f in findings)


def test_rootfs_directory(tmp_path, layers):
    root = tmp_path / "rootfs"
    for name, data in layers[0].items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    _, findings = _scan(str(root))
    assert _find(findings, asset_class="trust_store")
    assert _find(findings, library_id="openssl", ecosystem="deb")


def test_findings_are_deterministic(oci_image):
    first = sorted(f.id for f in _scan(str(oci_image))[1])
    second = sorted(f.id for f in _scan(str(oci_image))[1])
    assert first == second


def test_not_an_image_is_a_reported_failure(tmp_path):
    bogus = tmp_path / "bogus.tar"
    bogus.write_bytes(_tar({"hello.txt": b"hi"}, gz=False))
    result, findings = _scan(str(bogus))
    assert findings == [] and "not an image" in result.failures[0]["reason"]


def test_missing_image_is_a_reported_failure(tmp_path):
    result, _ = _scan(str(tmp_path / "missing.tar"))
    assert "image not found" in result.failures[0]["reason"]


@pytest.mark.parametrize("path,kind", [
    ("etc/ssl/certs/ca-certificates.crt", "trust"),
    ("usr/share/ca-certificates/mozilla/X.crt", None),
    ("usr/local/share/ca-certificates/corp.crt", "cert"),
    ("etc/nginx/ssl/server.key", "key"),
    ("etc/nginx/nginx.conf", "config"),
    ("var/lib/dpkg/status", "manifest"),
    ("usr/lib/x86_64-linux-gnu/libcrypto.so.3", "crypto_lib"),
    ("app/node_modules/jose/package.json", "npm_installed"),
    ("usr/bin/curl", "binary"),
    ("usr/share/doc/readme.txt", None),
])
def test_path_classification(path, kind):
    assert classify_path(path, 1000) == kind


def test_registered_in_the_collector_registry():
    assert REGISTRY["container"].plane == "built"
