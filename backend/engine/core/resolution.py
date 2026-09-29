"""Identity resolution: when findings from different collectors are one asset.

WHY
---
The same certificate can be parsed from a keystore (held), served on a live
endpoint (observed) and pinned in a binary (built). Counted three times it
inflates every total; merged blindly it can fuse two different certificates
that share a name. So identity is resolved on the strongest key the findings
actually share, in this order:

    fingerprint       certificate SHA-256 fingerprint
    serial_issuer     certificate serial + issuer DN
    public_key        SHA-256 of the public key (ties a KMIP / HSM key to its certificate)
    endpoint          host:port + asset class + algorithm (one endpoint yields several assets)
    key_id            KMIP unique identifier, PKCS#11 label, cloud KMS key id
    library           library@version inside the same image or project
    location          normalised file location + class + algorithm + line (exact duplicates)

Resolution is **conservative**. Findings merge only on an exact key match. Two
certificates with the same subject but different serials are *not* merged;
each gets a `possible_duplicates` link instead, for a person to decide.

WHAT A MERGE KEEPS
------------------
The best-evidenced finding becomes the asset. Every other finding in the group
becomes a `corroboration` record on it, carrying its own collector, plane,
provenance and confidence. `engine.core.corroboration` then takes the max
within a plane and noisy-OR across planes, so a keystore and a live handshake
agreeing lift confidence, and two views of one file do not.

EXPOSURE
--------
Each asset is tagged `internet`, `internal` or `unknown`, with the basis. For
an observed endpoint the address it answered on is a fact and wins; then the
exposure declared for its system in the estate register; then, for a bare
hostname, only its suffix (`.internal`, `.corp`, ...). Otherwise `unknown`.
"""

from __future__ import annotations

import ipaddress
import re
from collections import defaultdict

from engine.core.corroboration import plane_for
from models.schemas import RawCryptoFinding

KEY_ORDER = ("fingerprint", "serial_issuer", "public_key", "endpoint", "key_id", "library", "location")
_PLANE_RANK = {"observed": 3, "held": 2, "declared": 1, "built": 0}
_INTERNAL_SUFFIXES = (".internal", ".local", ".corp", ".lan", ".intra", ".intranet", ".home.arpa", ".localdomain")
# Networks that are not reachable from the internet. Deliberately explicit:
# Python's `is_private` also counts the RFC 5737 documentation ranges, which
# stand in for *public* addresses in examples and demos.
_INTERNAL_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "fc00::/7", "fe80::/10", "::1/128"))


def is_internal_ip(value: str) -> bool | None:
    """True for private / loopback / link-local, False for any other address, None if not an IP."""
    try:
        ip = ipaddress.ip_address(str(value).strip("[]"))
    except ValueError:
        return None
    return any(ip in net for net in _INTERNAL_NETWORKS if net.version == ip.version)


# --------------------------------------------------------------------------
# Normalisation
# --------------------------------------------------------------------------


def _hex(value: str | None) -> str | None:
    if not value:
        return None
    text = re.sub(r"[^0-9A-Fa-f]", "", str(value))
    return text.lower() or None


def normalise_serial(value) -> str | None:
    """Colon-hex ('8A:39:05') and decimal ('121878...') serials to one hex form."""
    if value in (None, ""):
        return None
    text = str(value).strip()
    try:
        number = int(text) if re.fullmatch(r"\d+", text) else int(re.sub(r"[^0-9A-Fa-f]", "", text), 16)
    except ValueError:
        return None
    return format(number, "x")


def normalise_dn(dn: str | None) -> str:
    if not dn:
        return ""
    parts = [p.strip().lower().replace(" ", "") for p in re.split(r",(?=\s*[A-Za-z]+=)", dn) if p.strip()]
    return ",".join(sorted(parts))


def endpoint_of(finding: RawCryptoFinding) -> str | None:
    """host:port for observed endpoint findings, else None."""
    if finding.source_type not in ("tls", "ssh"):
        return None
    location = (finding.raw_details or {}).get("endpoint") or finding.source_location
    location = re.sub(r"^[a-z]+://", "", str(location)).split("/", 1)[0].lower()
    return location or None


# --------------------------------------------------------------------------
# Keys
# --------------------------------------------------------------------------


def identity_keys(finding: RawCryptoFinding) -> dict[str, str]:
    """Every identity key this finding carries, strongest first."""
    d = finding.raw_details or {}
    keys: dict[str, str] = {}
    fingerprint = _hex(d.get("fingerprint_sha256") or d.get("sha256_fingerprint"))
    if fingerprint and len(fingerprint) == 64:
        keys["fingerprint"] = fingerprint
    serial = normalise_serial(finding.cert_serial or d.get("serial_number"))
    issuer = normalise_dn(finding.cert_issuer or d.get("issuer"))
    if serial and issuer:
        keys["serial_issuer"] = f"{serial}|{issuer}"
    public_key = _hex(d.get("public_key_sha256"))
    if public_key:
        keys["public_key"] = f"{public_key}|{finding.asset_class or ''}"
    endpoint = endpoint_of(finding)
    if endpoint:
        what = finding.algorithm or finding.key_exchange or finding.cipher_suite or finding.protocol or ""
        keys["endpoint"] = f"{endpoint}|{finding.asset_class or ''}|{what}".lower()
    key_id = d.get("Unique Identifier") or d.get("key_id") or d.get("KeyId") or d.get("CKA_ID")
    if key_id:
        keys["key_id"] = f"{d.get('discovered_by', '')}|{key_id}"
    if finding.asset_class == "crypto_library" and d.get("library_id"):
        scope = d.get("image_digest") or d.get("project") or ""
        keys["library"] = f"{scope}|{d['library_id']}|{d.get('library_version', 'unknown')}"
    location = re.sub(r":\d+$", "", finding.source_location or "")
    line = d.get("line") or (finding.source_location.rsplit(":", 1)[-1] if re.search(r":\d+$", finding.source_location or "") else "")
    what = finding.algorithm or finding.cipher_suite or finding.protocol or finding.key_exchange or ""
    keys["location"] = f"{location.lower()}|{finding.asset_class or ''}|{what}|{line}|{d.get('wire_name', '')}|{d.get('mode') or ''}"
    return keys


def exposure_for(finding: RawCryptoFinding) -> tuple[str, str]:
    """(exposure, basis). A declared value wins; an IP address is a fact; a name is only a hint."""
    d = finding.raw_details or {}
    if d.get("exposure") in ("internet", "internal"):
        return d["exposure"], d.get("exposure_basis", "declared")
    declared = d.get("declared_exposure")
    endpoint = endpoint_of(finding)
    if not endpoint:
        if declared in ("internet", "internal"):
            return declared, f"declared {declared} in the estate register for {d.get('system', 'its system')}"
        return "unknown", "not a network endpoint"
    host = endpoint.rsplit(":", 1)[0].strip("[]") if endpoint.count(":") == 1 or endpoint.startswith("[") else endpoint
    host = str(d.get("peer_ip") or host)
    internal = is_internal_ip(host)
    if internal is True:
        return "internal", f"{host} is a private address"
    if internal is False:
        return "internet", f"{host} is a public address"
    if declared in ("internet", "internal"):
        return declared, f"declared {declared} in the estate register for {d.get('system', 'its system')}"
    if host.endswith(_INTERNAL_SUFFIXES) or "." not in host:
        return "internal", f"'{host}' has an internal-only name"
    return "unknown", f"'{host}' is a name; its reachability is not established"


# --------------------------------------------------------------------------
# Resolution
# --------------------------------------------------------------------------


def _plane(finding: RawCryptoFinding) -> str:
    d = finding.raw_details or {}
    return plane_for(str(d.get("discovered_by") or finding.source_type), finding.source_type)


def _strength(finding: RawCryptoFinding) -> tuple:
    d = finding.raw_details or {}
    return (float(d.get("confidence") or 0), _PLANE_RANK.get(_plane(finding), 0), finding.id)


class _UnionFind:
    def __init__(self, n: int):
        self.parent = list(range(n))

    def find(self, i: int) -> int:
        while self.parent[i] != i:
            self.parent[i] = self.parent[self.parent[i]]
            i = self.parent[i]
        return i

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[max(ra, rb)] = min(ra, rb)


def _library_versions(findings: list[RawCryptoFinding], keys: list[dict[str, str]]) -> None:
    """Point version-less library evidence at the one known version in the same image or project.

    A binary without a banner says "OpenSSL, version unknown"; the image's package database says "libssl3 3.3.7".
    When a scope holds exactly one known version of a library, the version-less evidence can only be that
    library, so both carry the same identity key and merge. With two or more known versions the evidence is
    ambiguous and stays separate, as before.
    """
    known: dict[tuple[str, str], set[str]] = defaultdict(set)
    for f in findings:
        d = f.raw_details or {}
        if f.asset_class == "crypto_library" and d.get("library_id") and d.get("library_version") not in (None, "", "unknown"):
            known[(d.get("image_digest") or d.get("project") or "", d["library_id"])].add(str(d["library_version"]))
    for f, k in zip(findings, keys):
        d = f.raw_details or {}
        if "library" not in k or d.get("library_version") not in (None, "", "unknown"):
            continue
        scope = d.get("image_digest") or d.get("project") or ""
        versions = known.get((scope, d["library_id"]), set())
        if len(versions) == 1:
            k["library"] = f"{scope}|{d['library_id']}|{next(iter(versions))}"


def resolve(findings: list[RawCryptoFinding]) -> tuple[list[RawCryptoFinding], dict]:
    """Merge findings that are the same asset. Returns (assets, stats)."""
    keys = [identity_keys(f) for f in findings]
    _library_versions(findings, keys)
    uf = _UnionFind(len(findings))
    first_with: dict[tuple[str, str], int] = {}
    matched_on: dict[int, str] = {}
    for i, fkeys in enumerate(keys):
        for kind in KEY_ORDER:
            value = fkeys.get(kind)
            if value is None:
                continue
            other = first_with.setdefault((kind, value), i)
            if other != i:
                if uf.find(other) != uf.find(i):
                    matched_on[i] = matched_on.get(i, kind)
                uf.union(other, i)

    groups: dict[int, list[int]] = defaultdict(list)
    for i in range(len(findings)):
        groups[uf.find(i)].append(i)

    assets: list[RawCryptoFinding] = []
    merges_by_kind: dict[str, int] = defaultdict(int)
    cross_plane = 0
    for members in groups.values():
        ordered = sorted(members, key=lambda i: _strength(findings[i]), reverse=True)
        base = findings[ordered[0]]
        details = dict(base.raw_details or {})
        if len(ordered) > 1:
            kinds = sorted({matched_on[i] for i in members if i in matched_on}, key=KEY_ORDER.index)
            for kind in kinds:
                merges_by_kind[kind] += 1
            records = list(details.get("corroboration") or [])
            seen_at = set(details.get("also_seen_at") or [])
            planes = {_plane(base)}
            for i in ordered[1:]:
                other = findings[i]
                od = other.raw_details or {}
                plane = _plane(other)
                planes.add(plane)
                records.append({
                    "source": str(od.get("discovered_by") or other.source_type),
                    "plane": plane,
                    "provenance": od.get("provenance") or "imported",
                    "confidence": float(od.get("confidence") or 0.5),
                    "detail": f"Same asset ({kinds[0] if kinds else 'identity'}) at {other.source_location}.",
                    "location": other.source_location,
                })
                seen_at.add(other.source_location)
            details["corroboration"] = records
            details["also_seen_at"] = sorted(seen_at - {base.source_location})
            details["merged_ids"] = sorted(findings[i].id for i in ordered[1:])
            details["identity"] = {"matched_on": kinds, "members": len(ordered)}
            if base.asset_class == "crypto_library" and details.get("library_version") in (None, "", "unknown"):
                for i in ordered[1:]:                       # the version comes from whichever member states it
                    od = findings[i].raw_details or {}
                    if od.get("library_version") not in (None, "", "unknown"):
                        details["library_version"] = od["library_version"]
                        details["version_source"] = findings[i].source_location
                        # The PQC status was judged against "unknown"; take the verdict made with the version.
                        details.update({k: od[k] for k in ("pqc_capable", "pqc_native_from", "pqc_reason",
                                                           "upgrade_path") if k in od})
                        if "(version unknown)" in str(details.get("display_name", "")):
                            details["display_name"] = details["display_name"].replace(
                                "(version unknown)", str(od["library_version"]))
                        break
            if len(planes) > 1:
                cross_plane += 1
        exposure, basis = exposure_for(base)
        details.setdefault("exposure", exposure)
        details.setdefault("exposure_basis", basis)
        assets.append(base.model_copy(update={"raw_details": details}))

    _link_possible_duplicates(assets)
    stats = {
        "findings": len(findings),
        "assets": len(assets),
        "merged": len(findings) - len(assets),
        "cross_plane_assets": cross_plane,
        "merges_by_key": dict(merges_by_kind),
        "possible_duplicates": sum(1 for a in assets if a.raw_details.get("possible_duplicates")),
    }
    return assets, stats


def _link_possible_duplicates(assets: list[RawCryptoFinding]) -> None:
    """Same certificate subject, different serial: link, never merge."""
    by_subject: dict[str, list[RawCryptoFinding]] = defaultdict(list)
    for asset in assets:
        if asset.cert_subject:
            by_subject[normalise_dn(asset.cert_subject)].append(asset)
    for group in by_subject.values():
        if len(group) < 2:
            continue
        for asset in group:
            asset.raw_details["possible_duplicates"] = sorted(a.id for a in group if a is not asset)[:10]
