"""Drift: where one plane of evidence contradicts another.

A configuration is what someone intended; a handshake is what runs. When the
two disagree, the disagreement is itself a finding, and often the most useful
one in an audit: the reviewed config is not the one in service. Eight rules
(D1-D8, `engine/rules/drift.yaml`) each compare a declared or built fact with
an observed or held one, and emit a record with both pieces of evidence.

INPUTS
------
- findings: every collector finding, *before* identity resolution, so each
  side of a contradiction keeps its own location.
- declarations: posture facts (`tls_policy`, `ssh_policy` from the config
  collector) and the estate register (`system`: name, hosts, exposure), which
  is also how a config file without a server name is bound to a host.

Association is explicit, never guessed: by host:port, by public-key or
certificate identity, or by scope (the same image, system or project). A rule
that cannot associate two facts does not fire.
"""

from __future__ import annotations

import datetime as dt
import re
from functools import lru_cache
from pathlib import Path, PurePosixPath

import yaml

from collectors.base import stable_id
from engine.core.corroboration import plane_for
from engine.core.resolution import endpoint_of, is_internal_ip, normalise_dn, normalise_serial
from engine.kb.libraries import parse_version
from models.schemas import RawCryptoFinding

RULES_PATH = Path(__file__).resolve().parent / "rules" / "drift.yaml"
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@lru_cache(maxsize=1)
def rules() -> dict:
    raw = yaml.safe_load(RULES_PATH.read_text(encoding="utf-8"))
    raw["by_id"] = {r["id"]: r for r in raw["rules"]}
    return raw


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _plane(f: RawCryptoFinding) -> str:
    return plane_for(str((f.raw_details or {}).get("discovered_by") or f.source_type), f.source_type)


def _is_observed(f: RawCryptoFinding) -> bool:
    return _plane(f) == "observed"


def _hosts_of(f: RawCryptoFinding) -> set[str]:
    """Every host:port an observed finding answers for (name and IP)."""
    hosts = set()
    endpoint = endpoint_of(f)
    if endpoint:
        hosts.add(endpoint)
        port = endpoint.rsplit(":", 1)[-1] if ":" in endpoint else ""
        peer = (f.raw_details or {}).get("peer_ip")
        if peer and port:
            hosts.add(f"{peer}:{port}".lower())
    bound = (f.raw_details or {}).get("bound_host")
    if bound:
        hosts.add(str(bound).lower())
    return hosts


def _norm_hosts(hosts) -> set[str]:
    return {str(h).lower() for h in hosts or []}


def _hex(value) -> str:
    return re.sub(r"[^0-9a-f]", "", str(value or "").lower())


def _same_public_key(a, b) -> bool:
    """Public-key hashes match on their common prefix of at least 128 bits."""
    x, y = _hex(a), _hex(b)
    n = min(len(x), len(y))
    return n >= 32 and x[:n] == y[:n]


def _public_ip(host: str) -> str | None:
    address = host.rsplit(":", 1)[0] if host.count(":") == 1 or host.startswith("[") else host
    return address.strip("[]") if is_internal_ip(address) is False else None


def _ref(f: RawCryptoFinding) -> dict:
    return {"collector": str((f.raw_details or {}).get("discovered_by") or f.source_type),
            "plane": _plane(f), "location": f.source_location, "asset_id": f.id}


def _decl_ref(d: dict) -> dict:
    return {"collector": d.get("source", "config_scanner"), "plane": "declared", "location": d.get("location", "")}


class _Emitter:
    def __init__(self):
        self.records: list[dict] = []
        self._seen: set[tuple] = set()

    def emit(self, rule_id: str, *, subject: str, declared: str, observed: str, declared_ref: dict,
             observed_ref: dict, context: dict | None = None) -> None:
        key = (rule_id, subject, declared, observed)
        if key in self._seen:
            return
        self._seen.add(key)
        rule = rules()["by_id"][rule_id]
        fill = {"host": subject, "scope": subject, "declared": declared, "observed": observed, **(context or {})}
        self.records.append({
            "id": stable_id("drift", *key),
            "kind": "drift",
            "rule": rule_id,
            "title": rule["title"],
            "severity": rule["severity"],
            "subject": subject,
            "declared": {"summary": rule["declared"].format(**fill), "value": declared, **declared_ref},
            "observed": {"summary": rule["observed"].format(**fill), "value": observed, **observed_ref},
            "explain": rule["explain"].format(**fill),
            "evidence_refs": [declared_ref, observed_ref],
            "asset_ids": [r["asset_id"] for r in (declared_ref, observed_ref) if r.get("asset_id")],
        })


def _scope(f: RawCryptoFinding, host_system: dict[str, str]) -> str | None:
    d = f.raw_details or {}
    if d.get("system"):
        return f"system:{d['system']}"
    for host in _hosts_of(f):
        if host in host_system:
            return f"system:{host_system[host]}"
    if d.get("image_digest"):
        return f"image:{d.get('image') or d['image_digest'][:19]}"
    return None


def _project_contains(dep: RawCryptoFinding, binary: RawCryptoFinding) -> bool:
    project = (dep.raw_details or {}).get("project")
    if not project or (dep.raw_details or {}).get("image_digest"):
        return False
    return str(PurePosixPath(binary.source_location.replace("\\", "/"))).startswith(str(project).replace("\\", "/"))


# --------------------------------------------------------------------------
# Rules
# --------------------------------------------------------------------------


def _d1_d2(out: _Emitter, findings, declarations) -> None:
    cfg = rules()
    deprecated = set(cfg["deprecated_protocols"])
    weak = [m.upper() for m in cfg["weak_cipher_markers"]]
    observed = [f for f in findings if _is_observed(f) and f.source_type == "tls"]
    for decl in (d for d in declarations if d.get("kind") == "tls_policy"):
        hosts = _norm_hosts(decl.get("hosts")) | _norm_hosts([decl.get("bound_host")] if decl.get("bound_host") else [])
        if not hosts:
            continue
        allowed = decl.get("protocols")
        for f in observed:
            if not (_hosts_of(f) & hosts):
                continue
            subject = sorted(_hosts_of(f) & hosts)[0]
            if allowed and f.protocol in deprecated and f.protocol not in allowed:
                out.emit("D1", subject=subject, declared=" ".join(allowed), observed=f.protocol,
                         declared_ref=_decl_ref(decl), observed_ref=_ref(f))
            suite = (f.cipher_suite or "").upper()
            if (decl.get("ciphers") and not decl.get("weak_cipher_enabled") and suite
                    and any(m in suite for m in weak)):
                out.emit("D2", subject=subject, declared=decl["ciphers"], observed=f.cipher_suite,
                         declared_ref=_decl_ref(decl), observed_ref=_ref(f))


def _d3(out: _Emitter, findings, host_system) -> None:
    libs = [f for f in findings if f.asset_class == "crypto_library"
            and (f.raw_details or {}).get("library_id") == "openssl"]
    deps = [f for f in libs if "dependency" in str(f.raw_details.get("discovered_by"))]
    bins = [f for f in libs if "binary" in str(f.raw_details.get("discovered_by"))]
    for dep in deps:
        dv = parse_version(dep.raw_details.get("library_version"))
        if not dv or dv[0] < 3:
            continue
        for binary in bins:
            bv = parse_version(binary.raw_details.get("library_version"))
            if not bv or bv[0] >= 3:
                continue
            same = (_scope(dep, host_system) and _scope(dep, host_system) == _scope(binary, host_system)) \
                or _project_contains(dep, binary)
            if same:
                out.emit("D3", subject=_scope(dep, host_system) or dep.raw_details.get("project", ""),
                         declared=f"OpenSSL {dep.raw_details['library_version']}",
                         observed=f"OpenSSL {binary.raw_details['library_version']}",
                         declared_ref=_ref(dep), observed_ref=_ref(binary))


def _d4(out: _Emitter, findings, host_system) -> None:
    source = [f for f in findings if f.source_type in ("source", "container") and f.algorithm == "RSA"
              and f.key_size and "source" in str((f.raw_details or {}).get("discovered_by"))]
    certs = [f for f in findings if f.algorithm == "RSA" and f.key_size and f.cert_subject
             and _plane(f) in ("observed", "held")]
    for code in source:
        scope = _scope(code, host_system)
        if not scope:
            continue
        for cert in certs:
            if _scope(cert, host_system) == scope and cert.key_size < code.key_size:
                out.emit("D4", subject=scope, declared=f"RSA-{code.key_size}", observed=f"RSA-{cert.key_size}",
                         declared_ref=_ref(code), observed_ref=_ref(cert))


def _d5(out: _Emitter, findings) -> None:
    retired = set(rules()["retired_key_states"])
    managed = [f for f in findings if (f.raw_details or {}).get("public_key_sha256")
               and ((f.raw_details.get("lifecycle_state") or f.raw_details.get("State")
                     or f.raw_details.get("KeyState")) in retired)]
    live = [f for f in findings if _is_observed(f) and (f.raw_details or {}).get("public_key_sha256")]
    for key in managed:
        state = key.raw_details.get("lifecycle_state") or key.raw_details.get("State") or key.raw_details.get("KeyState")
        name = key.raw_details.get("display_name") or key.raw_details.get("Name") or key.source_location
        for f in live:
            if _same_public_key(key.raw_details["public_key_sha256"], f.raw_details["public_key_sha256"]):
                out.emit("D5", subject=str(name), declared=str(state), observed=endpoint_of(f) or f.source_location,
                         declared_ref=_ref(key), observed_ref=_ref(f), context={"key": name})


def _cert_ids(f: RawCryptoFinding) -> set[str]:
    d = f.raw_details or {}
    ids = set()
    fp = _hex(d.get("fingerprint_sha256") or d.get("sha256_fingerprint"))
    if len(fp) == 64:
        ids.add(f"fp:{fp}")
    serial = normalise_serial(f.cert_serial or d.get("serial_number"))
    issuer = normalise_dn(f.cert_issuer or d.get("issuer"))
    if serial and issuer:
        ids.add(f"si:{serial}|{issuer}")
    return ids


def _d6(out: _Emitter, findings, now: dt.datetime) -> None:
    held = [f for f in findings if _plane(f) == "held" and f.cert_validity_end]
    live = [f for f in findings if _is_observed(f) and f.cert_subject]
    for cert in held:
        try:
            end = dt.datetime.fromisoformat(str(cert.cert_validity_end).replace("Z", "+00:00"))
        except ValueError:
            continue
        if end.tzinfo is None:
            end = end.replace(tzinfo=dt.timezone.utc)
        if end >= now:
            continue
        ids = _cert_ids(cert)
        for f in live:
            if ids & _cert_ids(f):
                out.emit("D6", subject=cert.cert_subject or cert.source_location, declared=end.date().isoformat(),
                         observed=endpoint_of(f) or f.source_location, declared_ref=_ref(cert),
                         observed_ref=_ref(f), context={"subject": cert.cert_subject})


def _d7(out: _Emitter, findings, declarations) -> None:
    hybrids = set(rules()["pq_hybrid_kex"])
    live = [f for f in findings if f.source_type == "ssh" and _is_observed(f)]
    for decl in (d for d in declarations if d.get("kind") == "ssh_policy"):
        wanted = [k for k in decl.get("kex", []) if k in hybrids]
        hosts = _norm_hosts(decl.get("hosts")) | _norm_hosts([decl.get("bound_host")] if decl.get("bound_host") else [])
        if not wanted or not hosts:
            continue
        at_host = [f for f in live if _hosts_of(f) & hosts]
        if not at_host:
            continue
        offered = [f.raw_details.get("wire_name") for f in at_host if f.raw_details.get("name_list") == "kex_algorithms"]
        if not set(wanted) & set(offered):
            subject = sorted(_hosts_of(at_host[0]) & hosts)[0]
            out.emit("D7", subject=subject, declared=", ".join(wanted), observed=", ".join(offered[:4]) or "(none)",
                     declared_ref=_decl_ref(decl), observed_ref=_ref(at_host[0]))


def _d8(out: _Emitter, findings, declarations) -> None:
    internal = [d for d in declarations if d.get("exposure") == "internal" and d.get("hosts")]
    live = [f for f in findings if _is_observed(f)]
    for decl in internal:
        hosts = _norm_hosts(decl["hosts"])
        for f in live:
            if not (_hosts_of(f) & hosts):
                continue
            public = next((ip for ip in (_public_ip(h) for h in _hosts_of(f)) if ip), None)
            if public:
                subject = decl.get("name") or sorted(hosts)[0]
                out.emit("D8", subject=subject, declared="internal only", observed=public,
                         declared_ref=_decl_ref(decl), observed_ref=_ref(f))


def evaluate(findings: list[RawCryptoFinding], declarations: list[dict],
             now: dt.datetime | None = None) -> list[dict]:
    """Every drift record, most severe first."""
    now = now or dt.datetime.now(dt.timezone.utc)
    host_system = {h.lower(): d["name"] for d in declarations if d.get("kind") == "system"
                   for h in d.get("hosts", [])}
    out = _Emitter()
    _d1_d2(out, findings, declarations)
    _d3(out, findings, host_system)
    _d4(out, findings, host_system)
    _d5(out, findings)
    _d6(out, findings, now)
    _d7(out, findings, declarations)
    _d8(out, findings, declarations)
    return sorted(out.records, key=lambda r: (SEVERITY_ORDER.get(r["severity"], 9), r["rule"], r["subject"]))


def summarise(records: list[dict]) -> dict:
    by_rule: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for r in records:
        by_rule[r["rule"]] = by_rule.get(r["rule"], 0) + 1
        by_severity[r["severity"]] = by_severity.get(r["severity"], 0) + 1
    return {"total": len(records), "by_rule": by_rule, "by_severity": by_severity,
            "rules": [{k: v for k, v in r.items() if k in ("id", "title", "severity", "explain")}
                      for r in rules()["rules"]]}
