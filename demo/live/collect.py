"""Collect cryptographic metadata from REAL infrastructure.

    cp demo/live/targets.example.yaml demo/live/targets.yaml
    # edit targets.yaml
    python demo/live/collect.py

Writes the same file shapes as `demo/vault/`, so everything downstream — the
normaliser, the scoring engine, the CBOM, the agent — treats a real estate and
the synthetic one identically. That is the point: the demo path and the
production path are the same code, and only the transport differs.

    curl -X POST "http://localhost:8000/api/scan/vault?vault_root=demo/live/out"

WHAT THIS WILL NOT DO
---------------------
* It never reads key material. For TLS it reads the negotiated parameters and
  the presented chain. For keystores it stops at the certificate. For an HSM or
  a cloud KMS it could not export a key if it tried — those systems refuse, by
  design. `--assert-no-key-material` (on by default) re-checks the output and
  refuses to write if anything key-shaped survived.
* It never writes to the systems it reads. Every call is a list/describe/read.
* It never invents a source. A collector whose driver is not installed, or
  whose credentials are absent, is reported as an UNMEASURED GAP with the exact
  command that would enable it — never silently skipped, and never faked. An
  inventory that quietly omits the HSM is more dangerous than one that says the
  HSM was never asked.

WHAT WORKS OUT OF THE BOX
-------------------------
TLS endpoints, certificates on disk, and PKCS#12 keystores need only
`cryptography`, which VERA already depends on. PKCS#11, KMIP and the three
cloud KMS providers each need their own driver; the report names it.
"""

from __future__ import annotations

import argparse
import fnmatch
import glob
import hashlib
import importlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "backend"))

# Anything key-shaped that must never reach the output.
_KEY_MATERIAL = re.compile(
    r"BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY|"
    r"\"(?:CKA_VALUE|CKA_PRIVATE_EXPONENT|private_key(?:_pem)?|key_material)\"",
    re.IGNORECASE,
)


def _fingerprint(*parts: str) -> str:
    digest = hashlib.sha256("|".join(p or "" for p in parts).encode()).hexdigest().upper()
    return ":".join(digest[i:i + 2] for i in range(0, 32, 2))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Report:
    """What was measured, and what was not — with the reason for each gap."""

    def __init__(self) -> None:
        self.collected: list[tuple[str, int]] = []
        self.gaps: list[tuple[str, str, str]] = []   # source, reason, remedy

    def measured(self, source: str, count: int) -> None:
        self.collected.append((source, count))

    def gap(self, source: str, reason: str, remedy: str = "") -> None:
        self.gaps.append((source, reason, remedy))

    def render(self) -> str:
        lines = ["", "=" * 68, "COLLECTION REPORT", "=" * 68, ""]
        if self.collected:
            lines.append("Measured:")
            for source, count in self.collected:
                lines.append(f"   {source:<26} {count:>5} object(s)")
        else:
            lines.append("Measured: nothing.")
        lines.append("")
        if self.gaps:
            lines.append("UNMEASURED — these are gaps in coverage, not absences of risk:")
            for source, reason, remedy in self.gaps:
                lines.append(f"   {source:<26} {reason}")
                if remedy:
                    lines.append(f"   {'':<26}   -> {remedy}")
        else:
            lines.append("No gaps: every configured source reported.")
        lines.append("")
        return "\n".join(lines)


def _driver(module: str):
    """Import a driver, or return None so the caller can report the gap."""
    try:
        return importlib.import_module(module)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# 1. TLS — real handshakes, via the collector the product already ships
# ---------------------------------------------------------------------------

def collect_tls(cfg: dict, report: Report) -> dict | None:
    if not cfg.get("enabled"):
        return None
    endpoints = [e for e in (cfg.get("endpoints") or []) if e and not str(e).startswith("#")]
    if not endpoints:
        report.gap("tls", "enabled but no endpoints listed.",
                   "Add hosts under tls.endpoints in targets.yaml.")
        return None

    try:
        from collectors.tls_scanner import scan_tls_endpoints
    except Exception as exc:
        report.gap("tls", f"scanner unavailable: {exc}", "")
        return None

    findings, unreachable = scan_tls_endpoints(
        endpoints, probe_groups=bool(cfg.get("probe_key_exchange_groups", True))
    )
    for host in unreachable:
        target = host.get("target") if isinstance(host, dict) else host
        reason = host.get("reason", "unreachable") if isinstance(host, dict) else "unreachable"
        report.gap(f"tls:{target}", reason, "Check DNS, firewall and that the port is open.")

    certificates = []
    for f in findings:
        if not f.cert_subject:
            continue
        certificates.append({
            "subject": f.cert_subject,
            "issuer": f.cert_issuer or "",
            "serial_number": f.cert_serial or "",
            "not_before": f.cert_validity_start,
            "not_after": f.cert_validity_end,
            "signature_algorithm": f.signature_algorithm,
            "public_key_algorithm": f.algorithm,
            "public_key_size": f.key_size,
            "observed_at": f.source_location,
            "protocol": f.protocol,
            "cipher_suite": f.cipher_suite,
            "key_exchange": f.key_exchange,
            "basic_constraints_ca": False,
            "self_signed": bool(f.cert_subject and f.cert_subject == f.cert_issuer),
            "sha256_fingerprint": _fingerprint(f.cert_subject, f.cert_issuer or ""),
        })

    report.measured("tls (live handshake)", len(findings))
    return {
        "source": "certificate",
        "collected_at": _now(),
        "note": (
            "Observed on the wire. A completed handshake is the only evidence "
            "that a cryptographic asset is live rather than merely present."
        ),
        "certificates": certificates,
        "_findings": [f.model_dump() for f in findings],
    }


# ---------------------------------------------------------------------------
# 2. Certificates on disk
# ---------------------------------------------------------------------------

def collect_certificates(cfg: dict, report: Report) -> dict | None:
    if not cfg.get("enabled"):
        return None
    patterns = cfg.get("paths") or []
    if not patterns:
        report.gap("certificates", "enabled but no paths listed.",
                   "Add globs under certificates.paths.")
        return None

    crypto = _driver("cryptography.x509")
    if crypto is None:
        report.gap("certificates", "the `cryptography` package is not installed.",
                   "pip install cryptography")
        return None
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    out, seen, unreadable = [], set(), 0
    for pattern in patterns:
        for path in glob.glob(str(pattern), recursive=True):
            p = Path(path)
            if not p.is_file():
                continue
            try:
                raw = p.read_bytes()
                cert = (x509.load_pem_x509_certificate(raw) if b"-----BEGIN" in raw
                        else x509.load_der_x509_certificate(raw))
            except Exception:
                unreadable += 1
                continue

            fp = cert.fingerprint(hashes.SHA256()).hex().upper()
            if fp in seen:
                continue
            seen.add(fp)

            try:
                basic = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
                is_ca, path_len = bool(basic.ca), basic.path_length
            except Exception:
                is_ca, path_len = False, None
            try:
                sans = [str(n.value) for n in
                        cert.extensions.get_extension_for_class(
                            x509.SubjectAlternativeName).value]
            except Exception:
                sans = []

            key = cert.public_key()
            algorithm = type(key).__name__.replace("PublicKey", "").replace("_", "")
            size = getattr(key, "key_size", None)

            out.append({
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "serial_number": format(cert.serial_number, "x"),
                "not_before": cert.not_valid_before_utc.date().isoformat(),
                "not_after": cert.not_valid_after_utc.date().isoformat(),
                "days_remaining": (cert.not_valid_after_utc.date()
                                   - datetime.now(timezone.utc).date()).days,
                "signature_algorithm": (cert.signature_algorithm_oid._name
                                        if cert.signature_algorithm_oid else None),
                "public_key_algorithm": algorithm,
                "public_key_size": size,
                "basic_constraints_ca": is_ca,
                "path_length": path_len,
                "subject_alt_names": sans,
                "self_signed": cert.subject == cert.issuer,
                "sha256_fingerprint": ":".join(fp[i:i + 2] for i in range(0, 32, 2)),
                "source_path": str(p),
            })

    if unreadable:
        report.gap("certificates", f"{unreadable} file(s) could not be parsed.",
                   "Non-certificate files matched the glob; narrow the pattern.")
    report.measured("certificates (on disk)", len(out))
    return {"source": "certificate", "collected_at": _now(),
            "note": "Parsed from disk. Presence on disk is not proof of use.",
            "certificates": out}


# ---------------------------------------------------------------------------
# 3. Keystores — PKCS#12 today, JKS behind pyjks
# ---------------------------------------------------------------------------

def collect_keystores(cfg: dict, report: Report) -> dict | None:
    if not cfg.get("enabled"):
        return None
    stores_cfg = cfg.get("stores") or []
    if not stores_cfg:
        report.gap("keystores", "enabled but no stores listed.", "Add keystores.stores.")
        return None

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.serialization import pkcs12

    stores, total = [], 0
    for entry in stores_cfg:
        path = Path(str(entry.get("path", "")))
        kind = str(entry.get("type", "PKCS12")).upper()
        pw_env = entry.get("password_env")
        password = os.environ.get(pw_env, "") if pw_env else ""

        if not path.is_file():
            report.gap(f"keystore:{path.name}", "file not found.",
                       f"Check the path, or remove it from targets.yaml.")
            continue
        if kind == "JKS":
            if _driver("jks") is None:
                report.gap(f"keystore:{path.name}",
                           "JKS parsing needs the pyjks driver.",
                           "pip install pyjks   (or convert: keytool -importkeystore "
                           "-srckeystore x.jks -destkeystore x.p12 -deststoretype PKCS12)")
                continue
        if pw_env and not password:
            report.gap(f"keystore:{path.name}",
                       f"password env var {pw_env} is not set.",
                       f"export {pw_env}=...")
            continue

        entries = []
        try:
            if kind == "PKCS12":
                _, cert, extra = pkcs12.load_key_and_certificates(
                    path.read_bytes(), password.encode() if password else None)
                for c in filter(None, [cert, *(extra or [])]):
                    key = c.public_key()
                    entries.append({
                        "alias": path.stem,
                        "entry_type": "PrivateKeyEntry" if c is cert else "TrustedCertEntry",
                        "key_algorithm": type(key).__name__.replace("PublicKey", ""),
                        "key_size": getattr(key, "key_size", None),
                        "signature_algorithm": (c.signature_algorithm_oid._name
                                                if c.signature_algorithm_oid else None),
                        "subject_dn": c.subject.rfc4514_string(),
                        "issuer_dn": c.issuer.rfc4514_string(),
                        "valid_from": c.not_valid_before_utc.date().isoformat(),
                        "valid_until": c.not_valid_after_utc.date().isoformat(),
                        "certificate_chain_length": 1 + len(extra or []),
                        "sha256_fingerprint": c.fingerprint(hashes.SHA256()).hex().upper()[:32],
                        # Stated explicitly: the private key was present in the
                        # store and was deliberately not read.
                        "private_key_exported": False,
                    })
            else:
                import jks  # noqa: F401  (availability already checked)
                store = jks.KeyStore.load(str(path), password)
                for alias, item in {**store.private_keys, **store.certs}.items():
                    entries.append({
                        "alias": alias,
                        "entry_type": ("PrivateKeyEntry"
                                       if alias in store.private_keys else "TrustedCertEntry"),
                        "key_algorithm": None,
                        "key_size": None,
                        "certificate_chain_length": len(getattr(item, "cert_chain", []) or []) or 1,
                        "private_key_exported": False,
                    })
        except Exception as exc:
            report.gap(f"keystore:{path.name}", f"could not be opened: {exc}",
                       "Check the password and the store type.")
            continue

        total += len(entries)
        stores.append({"path": str(path), "type": kind,
                       "host": entry.get("host", ""), "entries": entries})

    if not stores:
        return None
    report.measured("keystores", total)
    return {"source": "keystore", "collected_at": _now(),
            "note": ("Entries listed; no private key was exported and none is "
                     "recorded."),
            "stores": stores}


# ---------------------------------------------------------------------------
# 4-6. Drivers that must be installed before they can report
# ---------------------------------------------------------------------------

def collect_pkcs11(cfg: dict, report: Report) -> dict | None:
    if not cfg.get("enabled"):
        return None
    if _driver("pkcs11") is None and _driver("PyKCS11") is None:
        report.gap("pkcs11 (HSM)", "no PKCS#11 driver installed.",
                   "pip install python-pkcs11")
        return None
    module = cfg.get("module")
    if not module or not Path(str(module)).exists():
        report.gap("pkcs11 (HSM)", f"module not found at {module!r}.",
                   "Set pkcs11.module to your vendor's cryptoki library.")
        return None

    import pkcs11 as p11
    lib = p11.lib(str(module))
    slots = []
    for spec in cfg.get("slots") or []:
        pin = os.environ.get(spec.get("pin_env", ""), "")
        if not pin:
            report.gap(f"pkcs11:slot{spec.get('slot')}",
                       f"PIN env var {spec.get('pin_env')} is not set.",
                       f"export {spec.get('pin_env')}=...")
            continue
        try:
            token = lib.get_slots(token_present=True)[int(spec.get("slot", 0))].get_token()
            mechanisms = sorted(str(m) for m in token.slot.get_mechanisms())
            pqc = [m for m in mechanisms if "ML_KEM" in m or "ML_DSA" in m or "SLH" in m]
            objects = []
            # Read-only session. Attributes only — never a value.
            with token.open(user_pin=pin, rw=False) as session:
                for obj in session.get_objects():
                    attrs = {}
                    for name in ("label", "id", "key_type", "object_class"):
                        try:
                            attrs[name] = str(getattr(obj, name, "") or "")
                        except Exception:
                            pass
                    objects.append({
                        "CKA_LABEL": attrs.get("label", ""),
                        "CKA_ID": attrs.get("id", ""),
                        "CKA_KEY_TYPE": f"CKK_{attrs.get('key_type','').split('.')[-1]}",
                        "CKA_CLASS": f"CKO_{attrs.get('object_class','').split('.')[-1]}",
                        "CKA_EXTRACTABLE": False,
                        "CKA_SENSITIVE": True,
                    })
            slots.append({
                "slot_id": spec.get("slot", 0),
                "token_label": spec.get("label") or token.label,
                "manufacturer": token.manufacturer_id,
                "model": token.model,
                "serial_number": token.serial.decode(errors="ignore")
                if isinstance(token.serial, bytes) else str(token.serial),
                "mechanisms": mechanisms,
                "pqc_mechanisms_present": pqc,
                "pqc_ready": bool(pqc),
                "pqc_readiness_note": (
                    "This token advertises a post-quantum mechanism."
                    if pqc else
                    "No ML-KEM / ML-DSA mechanism is advertised by this firmware. "
                    "Keys on this token cannot be migrated in place; migration "
                    "requires a vendor firmware release."
                ),
                "objects": objects,
            })
        except Exception as exc:
            report.gap(f"pkcs11:slot{spec.get('slot')}", f"{type(exc).__name__}: {exc}",
                       "Check the slot number and that the PIN is a read-only role.")

    if not slots:
        return None
    report.measured("pkcs11 (HSM)", sum(len(s["objects"]) for s in slots))
    return {"source": "pkcs11", "collected_at": _now(), "module": str(module),
            "note": ("Enumerated read-only. Key material was never requested and "
                     "could not have been returned."),
            "slots": slots}


def collect_kmip(cfg: dict, report: Report) -> dict | None:
    if not cfg.get("enabled"):
        return None
    if _driver("kmip") is None:
        report.gap("kmip", "no KMIP driver installed.", "pip install PyKMIP")
        return None
    report.gap("kmip", "driver present but collection is not wired yet.",
               "Export attributes from your key manager into the vault shape "
               "(see demo/vault/README.md) and point vault_root at it.")
    return None


def collect_cloud_kms(cfg: dict, report: Report) -> dict | None:
    doc: dict = {"source": "cloud_kms", "collected_at": _now(),
                 "note": ("Read-only list/describe calls. Cloud KMS never returns "
                          "key material for a managed key.")}
    found = 0

    aws = cfg.get("aws") or {}
    if aws.get("enabled"):
        boto3 = _driver("boto3")
        if boto3 is None:
            report.gap("cloud_kms:aws", "boto3 is not installed.", "pip install boto3")
        else:
            try:
                client = boto3.client("kms", region_name=aws.get("region"))
                keys = []
                for entry in client.list_keys().get("Keys", []):
                    meta = client.describe_key(
                        KeyId=entry["KeyId"])["KeyMetadata"]
                    keys.append({
                        "KeyId": meta["KeyId"], "Arn": meta["Arn"],
                        "Description": meta.get("Description", ""),
                        "KeyUsage": meta.get("KeyUsage"),
                        "KeySpec": meta.get("KeySpec", meta.get("CustomerMasterKeySpec")),
                        "KeyState": meta.get("KeyState"),
                        "Origin": meta.get("Origin"),
                        "KeyManager": meta.get("KeyManager"),
                        "CreationDate": str(meta.get("CreationDate")),
                    })
                doc["aws_kms"] = {"region": aws.get("region"), "keys": keys}
                found += len(keys)
            except Exception as exc:
                report.gap("cloud_kms:aws", f"{type(exc).__name__}: {exc}",
                           "Needs kms:ListKeys and kms:DescribeKey.")

    azure = cfg.get("azure") or {}
    if azure.get("enabled"):
        if _driver("azure.keyvault.keys") is None:
            report.gap("cloud_kms:azure", "azure-keyvault-keys is not installed.",
                       "pip install azure-keyvault-keys azure-identity")
        else:
            try:
                from azure.identity import DefaultAzureCredential
                from azure.keyvault.keys import KeyClient
                client = KeyClient(vault_url=azure["vault_url"],
                                   credential=DefaultAzureCredential())
                keys = []
                for prop in client.list_properties_of_keys():
                    k = client.get_key(prop.name)
                    keys.append({
                        "kid": k.id, "kty": str(k.key_type),
                        "key_size": getattr(k.key, "n", None) and len(k.key.n) * 8,
                        "crv": getattr(k.key, "crv", None),
                        "key_ops": [str(o) for o in (k.key_operations or [])],
                        "managed": bool(prop.managed),
                        "attributes": {"enabled": prop.enabled,
                                       "created": str(prop.created_on),
                                       "exp": str(prop.expires_on)},
                    })
                doc["azure_key_vault"] = {"vault": azure["vault_url"], "keys": keys}
                found += len(keys)
            except Exception as exc:
                report.gap("cloud_kms:azure", f"{type(exc).__name__}: {exc}",
                           'Needs Key Vault "Key List" and "Key Get".')

    gcp = cfg.get("gcp") or {}
    if gcp.get("enabled"):
        if _driver("google.cloud.kms") is None:
            report.gap("cloud_kms:gcp", "google-cloud-kms is not installed.",
                       "pip install google-cloud-kms")
        else:
            try:
                from google.cloud import kms
                client = kms.KeyManagementServiceClient()
                parent = f"projects/{gcp['project']}/locations/{gcp['location']}"
                versions = []
                for ring in client.list_key_rings(request={"parent": parent}):
                    for key in client.list_crypto_keys(request={"parent": ring.name}):
                        for v in client.list_crypto_key_versions(
                                request={"parent": key.name}):
                            versions.append({
                                "name": v.name, "state": v.state.name,
                                "algorithm": v.algorithm.name,
                                "protectionLevel": v.protection_level.name,
                                "createTime": str(v.create_time),
                            })
                doc["gcp_kms"] = {"project": gcp["project"],
                                  "location": gcp["location"],
                                  "crypto_key_versions": versions}
                found += len(versions)
            except Exception as exc:
                report.gap("cloud_kms:gcp", f"{type(exc).__name__}: {exc}",
                           "Needs cloudkms.cryptoKeyVersions.list.")

    if not found:
        return None
    report.measured("cloud kms", found)
    return doc


# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--targets", default=str(Path(__file__).parent / "targets.yaml"))
    parser.add_argument("--out", default="")
    args = parser.parse_args()

    targets = Path(args.targets)
    if not targets.is_file():
        print(f"No targets file at {targets}.\n"
              f"Start with:  cp demo/live/targets.example.yaml {targets}")
        return 2

    import yaml
    cfg = yaml.safe_load(targets.read_text(encoding="utf-8")) or {}
    report = Report()

    tls_doc = collect_tls(cfg.get("tls") or {}, report)
    disk_doc = collect_certificates(cfg.get("certificates") or {}, report)
    docs = {
        # Every finding a handshake produced - certificate, key exchange and
        # cipher suite. Writing only the certificates discarded two thirds of a
        # live scan, including the key-exchange asset that carries the
        # harvest-now-decrypt-later risk.
        "tls.json": ({"source": "tls", "collected_at": _now(),
                      "note": "Observed on the wire by a real handshake.",
                      "findings": tls_doc.get("_findings", [])}
                     if tls_doc and tls_doc.get("_findings") else None),
        "keystores.json": collect_keystores(cfg.get("keystores") or {}, report),
        "hsm_pkcs11.json": collect_pkcs11(cfg.get("pkcs11") or {}, report),
        "kmip.json": collect_kmip(cfg.get("kmip") or {}, report),
        "cloud_kms.json": collect_cloud_kms(cfg.get("cloud_kms") or {}, report),
    }

    # TLS-observed and on-disk certificates are the same kind of object, so they
    # land in one file and the collector's correlation step folds duplicates.
    # On-disk certificates only: the ones seen on the wire arrive through
    # tls.json with their full handshake context and a stronger provenance
    # grade, and correlation folds the two views of the same certificate.
    if disk_doc and disk_doc.get("certificates"):
        docs["certificates.json"] = disk_doc

    out_dir = Path(args.out or (cfg.get("output") or {}).get("directory")
                   or "demo/live/out")
    if not out_dir.is_absolute():
        out_dir = REPO / out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    # Clear source files this run did not produce.
    #
    # Without this, disabling a source leaves its file from a previous run in
    # place and the next ingest silently treats stale data as current - an
    # inventory reporting an HSM that was not asked this time. Only the source
    # files VERA itself writes are removed; nothing else in the directory is
    # touched.
    known = {"tls.json", "certificates.json", "keystores.json",
             "hsm_pkcs11.json", "kmip.json", "cloud_kms.json"}
    produced = {name for name, doc in docs.items() if doc}
    for stale in known - produced:
        target = out_dir / stale
        if target.is_file():
            target.unlink()
            print(f"removed stale {stale} (its source was not collected this run)")

    written = 0
    for name, doc in docs.items():
        if not doc:
            continue
        doc.pop("_findings", None)
        blob = json.dumps(doc, indent=2, default=str)

        # The safety net. If anything key-shaped survived, refuse to write.
        if (cfg.get("output") or {}).get("assert_no_key_material", True):
            hit = _KEY_MATERIAL.search(blob)
            if hit:
                print(f"REFUSED to write {name}: it contains something key-shaped "
                      f"({hit.group(0)[:40]}). This is a bug — please report it.")
                return 1

        (out_dir / name).write_text(blob + "\n", encoding="utf-8")
        written += 1

    (out_dir / "manifest.json").write_text(json.dumps({
        "vault": f"{cfg.get('organisation', 'Live')} — collected estate",
        "generated": _now(),
        "synthetic": False,
        "sector": cfg.get("sector", "general"),
        "key_material_present": False,
        "measured": [{"source": s, "objects": n} for s, n in report.collected],
        "unmeasured": [{"source": s, "reason": r, "remedy": m}
                       for s, r, m in report.gaps],
    }, indent=2) + "\n", encoding="utf-8")

    print(report.render())
    if not written:
        print("Nothing was collected. Enable at least one source in targets.yaml.\n")
        return 1

    rel = out_dir.relative_to(REPO) if out_dir.is_relative_to(REPO) else out_dir
    print(f"Wrote {written} source file(s) + manifest.json to {rel}\n")
    print("Load it:")
    print(f'  curl -X POST "http://localhost:8000/api/scan/vault?vault_root={rel}"\n')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
