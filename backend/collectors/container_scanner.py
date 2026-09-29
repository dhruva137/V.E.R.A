"""Container collector (plane: built): the cryptography inside an image.

INPUTS (no Docker daemon needed)
--------------------------------
- An image tarball from `docker save` (manifest.json + layer tars) or an OCI
  archive / layout (`skopeo copy ... oci-archive:`; oci-layout + index.json +
  blobs). Gzip-compressed layers are streamed.
- An unpacked root filesystem directory.

HOW
---
Layers are applied in order to build the merged view a running container
would see, honouring whiteouts (`.wh.<name>` deletes a lower-layer entry,
`.wh..wh..opq` makes a directory opaque). Nothing is extracted to disk: each
layer is streamed once to index it and once more to read the files selected
from the merged view. The existing collectors then run on the merged view:

    trust stores     /etc/ssl/certs, /etc/pki, ca-certificates bundles  -> one trust_store finding
    certificates     custom CA and server certificates                   -> keystore parser
    configurations   openssl.cnf, sshd_config, nginx, Apache, java.security, strongSwan -> config parser
    OS packages      dpkg status, apk installed                          -> dependency collector
    dependencies     lockfiles, site-packages METADATA, node_modules     -> dependency collector
    binaries         known crypto libraries first, then executables      -> binary collector

Every finding carries `image_digest`, `layer_digest`, `layer_index`,
`path_in_image` and `layer_origin`. The origin is `base` when the layer belongs
to the declared base image (a `base_layers` count, or a base image whose layer
digests are compared), `app` otherwise, and `unknown` when no base image was
declared, because an image does not record where its FROM line ended.

STATED LIMITATIONS
------------------
- RPM databases (sqlite / Berkeley DB) are not read; RPM-based images report
  their libraries through the binary layer only.
- Java `cacerts` (JKS) trust stores are counted but not parsed.
- Binaries are sampled beyond the first `max_binaries` (known crypto libraries
  always come first), and the sampling is reported in the stats.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import posixpath
import tarfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Callable

from collectors import binary_scanner, config_scanner, dependency_scanner
from collectors.base import MB, CollectResult, Limits, Timer, evidence, stable_id, walk
from engine.kb import libraries as kb
from models.schemas import RawCryptoFinding

COLLECTOR = "container_scanner"
MAX_IMAGE_BYTES = 2048 * MB
MAX_IMAGE_FILES = 200_000
MAX_BINARIES = 300
MAX_BINARY_BYTES = 64 * MB

_DISTRO_ROOTS = ("usr/share/ca-certificates/", "etc/pki/ca-trust/extracted/")
_CERT_HOMES = ("etc/", "usr/local/share/ca-certificates/", "app/", "opt/", "srv/", "home/", "root/")
_TRUST_BUNDLES = {"ca-certificates.crt", "ca-bundle.crt", "tls-ca-bundle.pem", "ca-bundle.trust.crt",
                  "cert.pem", "ca-certificates.pem"}
_CERT_SUFFIXES = (".pem", ".crt", ".cer")
_CONFIG_NAMES = {"openssl.cnf", "sshd_config", "ssh_config", "nginx.conf", "haproxy.cfg", "java.security",
                 "ipsec.conf", "swanctl.conf", "strongswan.conf", "httpd.conf", "apache2.conf", "ssl.conf",
                 "default-ssl.conf"}
_CONFIG_DIRS = ("etc/nginx/", "etc/apache2/", "etc/httpd/", "etc/ssh/", "etc/ipsec.d/", "etc/swanctl/",
                "etc/haproxy/")
_BINARY_DIRS = ("usr/bin/", "usr/sbin/", "bin/", "sbin/", "usr/local/bin/", "app/", "opt/", "srv/")
_LIB_DIRS = ("usr/lib/", "lib/", "usr/lib64/", "lib64/", "usr/local/lib/")


# --------------------------------------------------------------------------
# Image sources
# --------------------------------------------------------------------------


@dataclass
class LayerRef:
    index: int
    digest: str
    origin: str
    open: Callable[[], tarfile.TarFile]
    size: int = 0


@dataclass
class ImageSource:
    kind: str                     # docker-save | oci | rootfs
    name: str
    digest: str
    layers: list[LayerRef]
    base_note: str = ""
    rootfs: Path | None = None
    labels: dict = field(default_factory=dict)


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _open_layer_bytes(reader: Callable[[], bytes]) -> Callable[[], tarfile.TarFile]:
    def opener() -> tarfile.TarFile:
        data = reader()
        if data[:2] == b"\x1f\x8b":
            data = gzip.decompress(data)
        return tarfile.open(fileobj=io.BytesIO(data), mode="r:")
    return opener


def _origin(index: int, digest: str, base_layers: int | None, base_digests: set[str]) -> str:
    if base_digests:
        return "base" if digest in base_digests else "app"
    if base_layers is not None:
        return "base" if index < base_layers else "app"
    return "unknown"


class _Files:
    """Uniform read access to an image held in a tar or a directory."""

    def __init__(self, root: Path):
        self.root = root
        self._tar = tarfile.open(root, mode="r:*") if root.is_file() else None

    def read(self, name: str) -> bytes | None:
        name = name.lstrip("./")
        if self._tar is None:
            path = self.root / name
            return path.read_bytes() if path.is_file() else None
        try:
            member = self._tar.getmember(name)
        except KeyError:
            try:
                member = self._tar.getmember("./" + name)
            except KeyError:
                return None
        handle = self._tar.extractfile(member)
        return handle.read() if handle else None

    def size(self, name: str) -> int:
        name = name.lstrip("./")
        if self._tar is None:
            path = self.root / name
            return path.stat().st_size if path.is_file() else 0
        try:
            return self._tar.getmember(name).size
        except KeyError:
            return 0


def image_layer_digests(target: str | Path) -> set[str]:
    """Layer digests of an image, for comparing against a declared base image."""
    source = open_image(target)
    return {layer.digest for layer in source.layers}


def open_image(target: str | Path, *, base_layers: int | None = None,
               base_image: str | Path | None = None) -> ImageSource:
    """Resolve a tarball, OCI layout or rootfs directory into ordered layers."""
    root = Path(target)
    if not root.exists():
        raise FileNotFoundError(f"image not found: {root}")
    base_digests = image_layer_digests(base_image) if base_image else set()
    base_note = ("base layers from declared base image" if base_digests else
                 f"first {base_layers} layer(s) declared as base" if base_layers is not None else
                 "no base image declared; layer origin unknown")

    if root.is_dir() and not (root / "manifest.json").exists() and not (root / "index.json").exists():
        return ImageSource(kind="rootfs", name=root.name, digest=_sha256(str(root.resolve()).encode()),
                           layers=[], rootfs=root, base_note="unpacked root filesystem: one view, no layers")

    files = _Files(root)
    index_doc = files.read("index.json")
    manifest_doc = files.read("manifest.json")
    if index_doc and files.read("oci-layout") is not None:
        index = json.loads(index_doc)
        manifest_desc = index["manifests"][0]
        manifest_digest = manifest_desc["digest"]
        manifest = json.loads(files.read(f"blobs/{manifest_digest.replace(':', '/')}") or b"{}")
        config_blob = files.read(f"blobs/{manifest['config']['digest'].replace(':', '/')}") or b"{}"
        config = json.loads(config_blob)
        name = (manifest_desc.get("annotations") or {}).get("org.opencontainers.image.ref.name", root.stem)
        layers = []
        for i, desc in enumerate(manifest.get("layers", [])):
            blob = f"blobs/{desc['digest'].replace(':', '/')}"
            layers.append(LayerRef(i, desc["digest"], _origin(i, desc["digest"], base_layers, base_digests),
                                   _open_layer_bytes(lambda b=blob: files.read(b) or b""), desc.get("size", 0)))
        labels = (config.get("config") or {}).get("Labels") or {}
        return ImageSource("oci", name, manifest_digest, layers, base_note, labels=labels)

    if manifest_doc:
        entry = json.loads(manifest_doc)[0]
        config_blob = files.read(entry["Config"]) or b"{}"
        config = json.loads(config_blob)
        diff_ids = (config.get("rootfs") or {}).get("diff_ids") or []
        name = (entry.get("RepoTags") or [root.stem])[0]
        layers = []
        for i, layer_path in enumerate(entry["Layers"]):
            digest = diff_ids[i] if i < len(diff_ids) else _sha256(files.read(layer_path) or b"")
            layers.append(LayerRef(i, digest, _origin(i, digest, base_layers, base_digests),
                                   _open_layer_bytes(lambda p=layer_path: files.read(p) or b""),
                                   files.size(layer_path)))
        labels = (config.get("config") or {}).get("Labels") or {}
        return ImageSource("docker-save", name, _sha256(config_blob), layers, base_note, labels=labels)

    raise ValueError("not an image: no manifest.json (docker save) or index.json + oci-layout (OCI)")


# --------------------------------------------------------------------------
# Merged view
# --------------------------------------------------------------------------


@dataclass
class Entry:
    path: str                  # posix, no leading slash
    layer: int
    member: str
    size: int


def _norm(name: str) -> str:
    return posixpath.normpath(name.lstrip("./").lstrip("/")) if name.strip("./") else ""


def merged_view(source: ImageSource, result: CollectResult) -> dict[str, Entry]:
    """Apply layers in order, honouring whiteouts and opaque directories."""
    merged: dict[str, Entry] = {}
    total_bytes = 0
    for layer in source.layers:
        added: dict[str, Entry] = {}
        deleted: list[str] = []
        opaque: list[str] = []
        with layer.open() as tar:
            for member in tar:
                path = _norm(member.name)
                if not path:
                    continue
                directory, base = posixpath.split(path)
                if base == ".wh..wh..opq":
                    opaque.append(directory)
                    continue
                if base.startswith(".wh."):
                    deleted.append(posixpath.join(directory, base[len(".wh."):]))
                    continue
                if member.isreg():
                    total_bytes += member.size
                    added[path] = Entry(path, layer.index, member.name, member.size)
        for target in deleted:
            merged.pop(target, None)
            prefix = target + "/"
            for key in [k for k in merged if k.startswith(prefix)]:
                merged.pop(key)
        for directory in opaque:
            prefix = directory + "/" if directory else ""
            for key in [k for k in merged if k.startswith(prefix)]:
                merged.pop(key)
        merged.update(added)
        result.stats["whiteouts"] = result.stats.get("whiteouts", 0) + len(deleted) + len(opaque)
        if total_bytes > MAX_IMAGE_BYTES:
            result.fail(source.name, f"stopped: image exceeds {MAX_IMAGE_BYTES // MB} MB")
            break
        if len(merged) > MAX_IMAGE_FILES:
            result.fail(source.name, f"stopped: image exceeds {MAX_IMAGE_FILES} files")
            break
    return merged


# --------------------------------------------------------------------------
# Selection
# --------------------------------------------------------------------------


def classify_path(path: str, size: int) -> str | None:
    """Which collector reads this file: trust | cert | key | jks | config | manifest | npm_installed |
    crypto_lib | binary | None."""
    name = posixpath.basename(path)
    if name in _TRUST_BUNDLES and path.startswith(("etc/ssl/", "etc/pki/")):
        return "trust"
    if name == "cacerts":
        return "jks"
    if path.startswith(_DISTRO_ROOTS):
        return None  # individual distribution roots: the bundle already covers them
    if name.endswith(".key") or (f"/{path}".count("/private/") and name.endswith(_CERT_SUFFIXES)):
        return "key"
    if name.endswith(_CERT_SUFFIXES) and path.startswith(_CERT_HOMES):
        return "cert"
    if name in _CONFIG_NAMES or (path.startswith(_CONFIG_DIRS) and name.endswith((".conf", ".cnf"))):
        return "config"
    if "/node_modules/" in f"/{path}" and name == "package.json":
        # An installed package's own package.json names it; its dependency list
        # is not what the image ships. Only top-level installs are read.
        return "npm_installed" if path.count("node_modules/") == 1 else None
    if dependency_scanner.parser_for(PurePosixPath(path)) is not None:
        return "manifest"
    if size > MAX_BINARY_BYTES:
        return None
    if kb.for_native(name) is not None and path.startswith(_LIB_DIRS + _BINARY_DIRS):
        return "crypto_lib"
    if name.endswith((".jar", ".war", ".ear")):
        return "binary"
    if path.startswith(_BINARY_DIRS) and "." not in name:
        return "binary"
    return None


_PRIORITY = {"crypto_lib": 0, "binary": 1}


# --------------------------------------------------------------------------
# Collector
# --------------------------------------------------------------------------


class ContainerCollector:
    """Collector-contract implementation; see `collectors.base.Collector`.

    A target is a path, optionally with `#base_layers=N` or `#base=<path>`.
    """

    name = "container"
    plane = "built"
    label = "Container images"
    description = "OCI / docker-save tarballs and root filesystems: certs, configs, packages and binaries per layer."
    target_kinds = ("image", "path")

    def collect(self, targets: list[str], *, limits: Limits = Limits()) -> CollectResult:
        result = CollectResult(stats={"images": 0, "layers": 0, "files_in_view": 0, "files_read": 0,
                                      "binaries_sampled": 0, "binaries_skipped": 0, "whiteouts": 0,
                                      "bytes_read": 0})
        timer = Timer(limits)
        for raw in targets:
            path, _, options = str(raw).partition("#")
            base_layers, base_image = None, None
            for option in filter(None, options.split("&")):
                key, _, value = option.partition("=")
                if key == "base_layers" and value.isdigit():
                    base_layers = int(value)
                elif key == "base" and value:
                    base_image = value
            try:
                self.scan_image(path, result, limits=limits, timer=timer,
                                base_layers=base_layers, base_image=base_image)
            except (OSError, ValueError, KeyError, tarfile.TarError, json.JSONDecodeError) as exc:
                result.fail(path, f"image not read: {type(exc).__name__}: {exc}")
        result.stats["duration_ms"] = timer.elapsed_ms
        return result

    def scan_image(self, target: str, result: CollectResult, *, limits: Limits, timer: Timer,
                   base_layers: int | None = None, base_image: str | None = None) -> None:
        source = open_image(target, base_layers=base_layers, base_image=base_image)
        result.stats["images"] += 1
        result.stats["layers"] += len(source.layers)
        image_ctx = {"image": source.name, "image_digest": source.digest, "image_kind": source.kind,
                     "base_note": source.base_note}

        if source.kind == "rootfs":
            entries = self._rootfs_entries(source.rootfs, result, limits)

            def read(entry: Entry) -> bytes:
                return (source.rootfs / entry.member).read_bytes()

            layer_meta = {0: ("rootfs", "unknown")}
        else:
            entries = merged_view(source, result)
            layer_meta = {l.index: (l.digest, l.origin) for l in source.layers}
            read = None
        result.stats["files_in_view"] += len(entries)

        selected: dict[str, tuple[Entry, str]] = {}
        binaries: list[tuple[int, str, Entry]] = []
        for path, entry in entries.items():
            kind = classify_path(path, entry.size)
            if kind in ("crypto_lib", "binary"):
                binaries.append((_PRIORITY[kind], path, entry))
            elif kind:
                selected[path] = (entry, kind)
        binaries.sort()
        for _prio, path, entry in binaries[:MAX_BINARIES]:
            selected[path] = (entry, "binary")
        result.stats["binaries_skipped"] += max(len(binaries) - MAX_BINARIES, 0)

        contents: dict[str, bytes] = {}
        if read is not None:
            for path, (entry, _kind) in selected.items():
                contents[path] = read(entry)
        else:
            wanted: dict[int, dict[str, str]] = {}
            for path, (entry, _kind) in selected.items():
                wanted.setdefault(entry.layer, {})[entry.member] = path
            for layer in source.layers:
                if layer.index not in wanted or timer.expired:
                    continue
                with layer.open() as tar:
                    for member in tar:
                        path = wanted[layer.index].get(member.name)
                        if path is None or not member.isreg():
                            continue
                        handle = tar.extractfile(member)
                        if handle is not None:
                            contents[path] = handle.read()
        if timer.expired:
            result.fail(target, f"stopped after {limits.timeout_s:.0f}s (timeout)")

        packages_by_layer: dict[int, list[dependency_scanner.Package]] = {}
        trust_roots: list[tuple[str, Entry, list]] = []
        for path, data in sorted(contents.items()):
            entry, kind = selected[path]
            result.stats["files_read"] += 1
            result.stats["bytes_read"] += len(data)
            digest, origin = layer_meta.get(entry.layer, ("unknown", "unknown"))
            ctx = {**image_ctx, "layer_digest": digest, "layer_index": entry.layer, "layer_origin": origin,
                   "path_in_image": "/" + path}
            location = f"{source.name}!/{path}"
            found: list[RawCryptoFinding] = []
            inner = kind
            if kind == "binary":
                sub = binary_scanner.scan_blob(data, location, limits=limits, context=ctx)
                found = sub.findings
                result.failures.extend(sub.failures)
                result.stats["binaries_sampled"] += 1
                inner = "binary"
            elif kind == "config":
                text = data.decode("utf-8", errors="replace")
                found = config_scanner.scan_text(text, location)
                result.declarations.extend({**decl, "image": source.name, "image_digest": source.digest}
                                           for decl in config_scanner.declarations(text, location))
            elif kind == "cert":
                found = _certificates(data, location)
                inner = "certificate"
            elif kind == "key":
                found = binary_scanner.pem_findings(data, location, context=ctx)
                inner = "secret"
            elif kind == "trust":
                trust_roots.append((path, entry, _roots(data)))
                continue
            elif kind == "jks":
                result.fail(location, "Java cacerts (JKS) trust store counted, not parsed")
                continue
            elif kind in ("manifest", "npm_installed"):
                text = data.decode("utf-8", errors="replace")
                try:
                    pkgs = (_npm_installed(PurePosixPath(path), text) if kind == "npm_installed"
                            else dependency_scanner.packages_in_text(PurePosixPath(path), text))
                except (ValueError, KeyError, TypeError) as exc:
                    result.fail(location, f"manifest parse failed: {type(exc).__name__}: {exc}")
                    continue
                packages_by_layer.setdefault(entry.layer, []).extend(pkgs)
                continue
            for finding in found:
                result.findings.append(_stamp(finding, inner, ctx, location))

        for layer_index, pkgs in sorted(packages_by_layer.items()):
            digest, origin = layer_meta.get(layer_index, ("unknown", "unknown"))
            ctx = {**image_ctx, "layer_digest": digest, "layer_index": layer_index, "layer_origin": origin}
            found, _ = dependency_scanner.findings_from_packages(pkgs, ctx, location_prefix=f"{source.name}!/")
            for finding in found:
                path_in_image = "/" + finding.raw_details["manifests"][0].split("!/", 1)[-1]
                finding.raw_details["path_in_image"] = path_in_image
                result.findings.append(_stamp(finding, "dependency", {**ctx, "path_in_image": path_in_image},
                                              finding.source_location))

        for path, entry, roots in trust_roots:
            digest, origin = layer_meta.get(entry.layer, ("unknown", "unknown"))
            ctx = {**image_ctx, "layer_digest": digest, "layer_index": entry.layer, "layer_origin": origin,
                   "path_in_image": "/" + path}
            finding = _trust_store(roots, f"{source.name}!/{path}", ctx)
            if finding is not None:
                result.findings.append(finding)

    def _rootfs_entries(self, root: Path, result: CollectResult, limits: Limits) -> dict[str, Entry]:
        entries = {}
        for path in walk(root, limits, result, skip_dirs=frozenset({"proc", "sys", "dev"})):
            rel = path.relative_to(root).as_posix()
            try:
                size = path.stat().st_size
            except OSError:
                continue
            entries[rel] = Entry(rel, 0, rel, size)
        return entries


def _stamp(finding: RawCryptoFinding, inner: str, ctx: dict, location: str) -> RawCryptoFinding:
    """Mark a sub-collector's finding as seen inside this image."""
    details = dict(finding.raw_details or {})
    details.update(ctx)
    details["inner_collector"] = details.get("discovered_by", inner)
    details["discovered_by"] = f"{COLLECTOR}/{inner}"
    refs = list(details.get("evidence_refs") or [])
    refs.insert(0, evidence(COLLECTOR, location, digest=ctx.get("image_digest"), layer=ctx.get("layer_digest")))
    details["evidence_refs"] = refs[:10]
    if "display_name" not in details:
        details["display_name"] = f"{finding.algorithm or finding.cipher_suite or finding.protocol or 'artefact'} in {ctx['path_in_image']}"
    tags = list(finding.tags) + ["container-scan", f"layer:{ctx.get('layer_origin', 'unknown')}"]
    return finding.model_copy(update={
        "id": stable_id(COLLECTOR, ctx.get("image_digest"), finding.source_location, finding.id),
        "source_type": "container",
        "raw_details": details,
        "tags": tags,
    })


def _certificates(data: bytes, location: str) -> list[RawCryptoFinding]:
    from cryptography import x509

    from collectors.keystore_scanner import _classify_certificate, _finding_from_certificate

    findings = []
    try:
        certs = x509.load_pem_x509_certificates(data)
    except ValueError:
        try:
            certs = [x509.load_der_x509_certificate(data)]
        except ValueError:
            return []
    for cert in certs:
        finding = _finding_from_certificate(cert, PurePosixPath(location), _classify_certificate(cert))
        finding.raw_details.update({"provenance": "artifact_parsed", "plane": "held"})
        findings.append(finding)
    return findings


def _roots(data: bytes) -> list:
    from cryptography import x509

    try:
        return x509.load_pem_x509_certificates(data)
    except ValueError:
        return []


def _trust_store(roots: list, location: str, ctx: dict) -> RawCryptoFinding | None:
    """One finding for a system trust bundle, with the algorithm mix of its roots."""
    from collectors.tls_scanner import get_algorithm_details

    if not roots:
        return None
    mix: Counter = Counter()
    for cert in roots:
        algorithm, key_size, curve = get_algorithm_details(cert.public_key())
        mix[f"{algorithm}-{curve or key_size}"] += 1
    dominant, count = mix.most_common(1)[0]
    algorithm, _, size = dominant.partition("-")
    classical = sum(n for k, n in mix.items() if k.split("-")[0] in {"RSA", "ECDSA", "EC", "DSA", "Ed25519", "Ed448"})
    details = {
        **ctx,
        "discovered_by": f"{COLLECTOR}/certificate",
        "inner_collector": "trust_store",
        "plane": "held",
        "provenance": "artifact_parsed",
        "confidence": 0.90,
        "roots": len(roots),
        "by_algorithm": dict(sorted(mix.items())),
        "classical_roots": classical,
        "pqc_roots": len(roots) - classical,
        "evidence_refs": [evidence(COLLECTOR, location, digest=ctx.get("image_digest"), layer=ctx.get("layer_digest"))],
        "display_name": f"Trust store {ctx['path_in_image']} ({len(roots)} roots)",
    }
    return RawCryptoFinding(
        id=stable_id(COLLECTOR, ctx.get("image_digest"), "trust", location),
        source_type="container", source_location=location, asset_class="trust_store",
        algorithm=algorithm, key_size=int(size) if size.isdigit() else None, usage="signing",
        tags=["container-scan", "trust-store", f"layer:{ctx.get('layer_origin', 'unknown')}"],
        raw_details=details,
    )


def _npm_installed(path: PurePosixPath, text: str) -> list[dependency_scanner.Package]:
    data = json.loads(text)
    name, version = data.get("name"), data.get("version")
    if not name:
        return []
    return [dependency_scanner.Package("npm", name, dependency_scanner._exact_or_none(version), version,
                                       path, 1, "installed")]


def scan_images(paths: list[str]) -> tuple[list[RawCryptoFinding], list[dict]]:
    """Function-style entry point, matching the other collectors."""
    result = ContainerCollector().collect(paths)
    return result.findings, result.failures
