"""Offline founder demo — score demo/vault with no server and no network.

WHAT THIS IS
------------
The CISO walkthrough in README.md talks to localhost:8000. This script is the
same beats without a process: adapters declare coverage, the vault collector
ingests PKCS#11 / KMIP / cloud-KMS / keystore / cert shapes, the engine ranks
them, and the process exits non-zero if a safety or correlation invariant
fails.

It must work with only demo/vault/ on disk. It never opens a socket.

Run:  python demo/showcase/run_demo.py
      python demo/showcase/run_demo.py --quiet
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND = REPO_ROOT / "backend"
VAULT = REPO_ROOT / "demo" / "vault"
EXPECTED_PATH = Path(__file__).parent / "expected.json"

if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

PEM_MARKERS = ("BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY", "BEGIN EC PRIVATE KEY")


def load_expected() -> dict[str, Any]:
    return json.loads(EXPECTED_PATH.read_text(encoding="utf-8"))


def adapter_cards(vault_root: Path | None = None) -> list[dict[str, Any]]:
    from adapters import describe_adapters

    return describe_adapters(vault_root or VAULT)


def collect(vault_root: Path | None = None, *, correlate: bool = True):
    from collectors.vault_collector import scan_vault

    return scan_vault(vault_root or VAULT, correlate_sources=correlate)


def score_findings(findings) -> list:
    from engine.qirs import assign_risk_level, order_assets, score_assets
    from engine.regulatory import map_regulatory
    from engine.threat_model import ThreatModel
    from models.schemas import CryptoAsset

    assets = [
        CryptoAsset(
            **finding.model_dump(),
            name=(finding.raw_details or {}).get("display_name") or finding.id,
        )
        for finding in findings
    ]
    model = ThreatModel()
    assets = score_assets(assets, model)
    assets = map_regulatory(assets, org_persona="Banking")
    for asset in assets:
        asset.risk_level = assign_risk_level(asset)
    return order_assets(assets, model)


def pack_unplug() -> dict[str, Any]:
    """Payments pack out: language changes, engine numbers do not live here."""
    from engine.packs import PACKS, PackRegistry

    registry = PackRegistry()
    for pack_id in PACKS:
        registry.enable(pack_id)
    plugged = registry.resolved("payments")
    registry.disable("pack.payments")
    unplugged = registry.resolved("payments")
    return {
        "packs_applied_on": plugged["packs_applied"],
        "packs_applied_off": unplugged["packs_applied"],
        "controls_on": len(plugged["controls"]),
        "controls_off": len(unplugged["controls"]),
        "pci_framing_on": "PCI" in plugged["board_framing"],
        "pci_framing_off": "PCI" in unplugged["board_framing"],
        "baseline_survives": (
            unplugged["packs_applied"] == ["pack.baseline"]
            and bool(unplugged["controls"])
            and bool(unplugged["board_framing"].strip())
        ),
    }


def _dump(findings) -> str:
    return json.dumps([f.model_dump() for f in findings], default=str)


def build_report(vault_root: Path | None = None) -> dict[str, Any]:
    root = vault_root or VAULT
    cards = adapter_cards(root)
    raw, raw_errors = collect(root, correlate=False)
    findings, errors = collect(root, correlate=True)
    assets = score_findings(findings) if findings else []

    vulnerable = [a for a in assets if a.quantum_vulnerable]
    by_h = sorted(vulnerable, key=lambda a: -a.h_score)
    by_t = sorted(vulnerable, key=lambda a: -a.t_score)
    by_qirs = sorted(assets, key=lambda a: -a.qirs)
    blocked = [a for a in assets if (a.raw_details or {}).get("change_blocked")]

    by_source: dict[str, int] = {}
    for finding in findings:
        key = (finding.raw_details or {}).get("discovered_by", "unknown")
        by_source[key] = by_source.get(key, 0) + 1

    corroborations = [
        int((f.raw_details or {}).get("corroboration_count") or 1)
        for f in findings
    ]

    return {
        "vault": str(root),
        "adapter_cards": cards,
        "raw_count": len(raw),
        "asset_count": len(assets),
        "correlated_away": len(raw) - len(findings),
        "errors": errors or raw_errors,
        "findings_blob": _dump(findings),
        "by_source": by_source,
        "max_corroboration": max(corroborations) if corroborations else 0,
        "blocked_count": len(blocked),
        "blocked_names": [a.name for a in blocked],
        "qirs_top": _summarise(by_qirs[0]) if by_qirs else None,
        "rank1": _summarise(assets[0]) if assets else None,
        "rank1_most_exposed": _most_exposed(assets),
        "top_hndl": _summarise(by_h[0]) if by_h else None,
        "top_tnfl": _summarise(by_t[0]) if by_t else None,
        "pack_unplug": pack_unplug(),
    }


def _summarise(asset) -> dict[str, Any]:
    raw = asset.raw_details or {}
    return {
        "id": asset.id,
        "name": asset.name,
        "asset_class": asset.asset_class,
        "qirs": round(asset.qirs, 4),
        "h_score": round(asset.h_score, 4),
        "t_score": round(asset.t_score, 4),
        "priority_rank": asset.priority_rank,
        "change_blocked": bool(raw.get("change_blocked")),
        "persona": asset.persona,
        "slack_months": asset.slack_months,
        "mosca_category": asset.mosca_category,
        "mosca_margin_years": asset.mosca_margin_years,
    }


def _most_exposed(assets) -> bool:
    """Rank 1 is in the most urgent Mosca category present, with the widest margin in it."""
    from engine import mosca

    vulnerable = [a for a in assets if a.quantum_vulnerable]
    if not vulnerable:
        return False
    top = min(mosca.category_rank(a.mosca_category) for a in vulnerable)
    in_top = [a for a in vulnerable if mosca.category_rank(a.mosca_category) == top]
    widest = max(a.mosca_margin_years for a in in_top if a.mosca_margin_years is not None)
    first = assets[0]
    return mosca.category_rank(first.mosca_category) == top and first.mosca_margin_years == widest


def _in_range(value: float, spec) -> bool:
    if isinstance(spec, (list, tuple)) and len(spec) == 2:
        return spec[0] <= value <= spec[1]
    return value == spec


def check_invariants(report: dict[str, Any], expected: dict[str, Any] | None = None) -> list[str]:
    """Return human-readable failures. Empty list means the demo is showable."""
    expected = expected or load_expected()
    failures: list[str] = []

    blob = report.get("findings_blob") or ""
    for marker in PEM_MARKERS:
        if marker in blob:
            failures.append(f"key material marker survived into findings: {marker}")
    from engine.intake.scrub import FORBIDDEN
    for field in sorted(FORBIDDEN):
        if f'"{field}"' in blob:
            failures.append(f"forbidden field {field} survived into findings")
    if expected.get("key_material_present") is not False:
        failures.append("expected.json must declare key_material_present: false")

    if not _in_range(report["asset_count"], expected["assets_range"]):
        failures.append(
            f"asset count {report['asset_count']} outside {expected['assets_range']}"
        )
    if not _in_range(report["raw_count"], expected["raw_objects"]):
        failures.append(
            f"raw objects {report['raw_count']} != {expected['raw_objects']}"
        )
    if not _in_range(report["correlated_away"], expected["correlated_away_range"]):
        failures.append(
            f"correlation dropped {report['correlated_away']}, "
            f"expected {expected['correlated_away_range']}"
        )
    if report["max_corroboration"] > expected.get("max_corroboration", 2):
        failures.append(
            f"corroboration_count {report['max_corroboration']} "
            "looks like over-merge, not two sensors on one cert"
        )
    if not _in_range(report["blocked_count"], expected["change_blocked_range"]):
        failures.append(
            f"change_blocked {report['blocked_count']} "
            f"outside {expected['change_blocked_range']}"
        )

    sources = set(report["by_source"])
    missing = set(expected["sources_required"]) - sources
    if missing:
        failures.append(f"vault missing sensors: {sorted(missing)}")
    if report["by_source"].get("vault_pkcs11") != expected["by_source"]["vault_pkcs11"]:
        failures.append(
            "PKCS#11 objects were merged away — correlation is not sane"
        )

    qirs_top = report.get("qirs_top") or {}
    if qirs_top.get("asset_class") != expected["qirs_top_asset_class"]:
        failures.append(
            f"QIRS-top class {qirs_top.get('asset_class')!r} "
            f"!= {expected['qirs_top_asset_class']!r}"
        )
    needle = expected["qirs_top_label_contains"]
    if needle not in (qirs_top.get("name") or "") and needle not in (qirs_top.get("id") or ""):
        failures.append(f"QIRS-top is not {needle}: {qirs_top}")
    if expected["qirs_top_change_blocked"] and not qirs_top.get("change_blocked"):
        failures.append("QIRS-top firmware key is not change_blocked")
    if qirs_top and not _in_range(qirs_top["qirs"], expected["qirs_top_range"]):
        failures.append(
            f"QIRS {qirs_top['qirs']} outside {expected['qirs_top_range']}"
        )

    rank1 = report.get("rank1") or {}
    if expected["priority_rank1_most_exposed"] and not report.get("rank1_most_exposed"):
        failures.append(
            f"migration rank-1 is not the most exposed asset under Mosca: {rank1.get('name')}"
        )

    top_h, top_t = report.get("top_hndl") or {}, report.get("top_tnfl") or {}
    if expected["hndl_tnfl_distinct"] and top_h and top_t:
        if top_h.get("id") == top_t.get("id"):
            failures.append("top HNDL and top TNFL are the same asset")
        allowed = set(expected["tnfl_top_classes_allowed"])
        if top_t.get("asset_class") not in allowed:
            failures.append(
                f"top TNFL class {top_t.get('asset_class')!r} not in {sorted(allowed)}"
            )

    ids = [c["id"] for c in report["adapter_cards"]]
    if ids != expected["adapter_ids"]:
        failures.append(f"adapter ids {ids} != {expected['adapter_ids']}")
    for card in report["adapter_cards"]:
        contract = card.get("coverage_contract") or {}
        if not contract.get("cannot_prove"):
            failures.append(f"{card['id']} coverage_contract missing cannot_prove")
        if card["id"] != "tls" and card.get("measurement", {}).get("mode") != "file_dump":
            failures.append(f"{card['id']} should be measurable via file dump")
        if card["id"] == "tls" and not expected.get("tls_vault_file"):
            if card.get("measurement", {}).get("mode") == "file_dump":
                failures.append("tls.json appeared in demo/vault — it is a live-only source")

    packs = report.get("pack_unplug") or {}
    if not packs.get("baseline_survives"):
        failures.append("unplugging pack.payments left no baseline content")
    if packs.get("controls_on", 0) <= packs.get("controls_off", 0):
        failures.append("payments pack did not add controls over baseline")

    if report.get("errors"):
        failures.append(f"collector reported gaps: {report['errors']}")

    return failures


def _print_report(report: dict[str, Any]) -> None:
    print(f"vault: {report['vault']}")
    print(f"raw objects: {report['raw_count']}  ->  assets: {report['asset_count']}  "
          f"(correlated away: {report['correlated_away']})")
    print("by source: " + " | ".join(
        f"{k}={v}" for k, v in sorted(report["by_source"].items())
    ))
    print()
    print("adapter coverage (file dump != live):")
    for card in report["adapter_cards"]:
        contract = card["coverage_contract"]
        mode = (card.get("measurement") or {}).get("mode", "?")
        cannot = "; ".join(contract.get("cannot_prove") or [])
        print(f"  {card['id']:<12}  {mode:<12}  cannot prove: {cannot}")
    print()
    qirs_top, rank1 = report["qirs_top"], report["rank1"]
    print("QIRS-top (firmware):     "
          f"{qirs_top['name']}  qirs={qirs_top['qirs']}  "
          f"blocked={qirs_top['change_blocked']}")
    print("backlog rank-1:          "
          f"{rank1['name']}  qirs={rank1['qirs']}  "
          f"blocked={rank1['change_blocked']}  slack={rank1['slack_months']}")
    print("top HNDL:                "
          f"{report['top_hndl']['name']}  H={report['top_hndl']['h_score']}  "
          f"class={report['top_hndl']['asset_class']}")
    print("top TNFL:                "
          f"{report['top_tnfl']['name']}  T={report['top_tnfl']['t_score']}  "
          f"class={report['top_tnfl']['asset_class']}")
    print(f"change_blocked:          {report['blocked_count']}  "
          f"{report['blocked_names']}")
    packs = report["pack_unplug"]
    print()
    print("pack.payments unplug:    "
          f"{packs['packs_applied_on']} -> {packs['packs_applied_off']}  "
          f"controls {packs['controls_on']} -> {packs['controls_off']}  "
          f"PCI framing {packs['pci_framing_on']} -> {packs['pci_framing_off']}")
    print("                         Bel/K/QIRS are engine outputs; packs only "
          "change what is said about them.")
    print()
    print("live demo (server on :8000):")
    print('  curl -s -X POST "http://localhost:8000/api/scan/vault?org_persona=Banking"')
    print('  curl -s "http://localhost:8000/api/axis-extremes?count=5"')
    print("  curl -s http://localhost:8000/api/adapters")
    print("  See demo/showcase/README.md for the full operator script.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--quiet", action="store_true", help="print only failures")
    parser.add_argument(
        "--vault", type=Path, default=None,
        help="vault directory (default: demo/vault)",
    )
    args = parser.parse_args(argv)

    root = args.vault or VAULT
    if not root.is_dir():
        print(f"vault not found: {root}", file=sys.stderr)
        print("run: python demo/vault/make_vault.py", file=sys.stderr)
        return 2

    report = build_report(root)
    failures = check_invariants(report)
    if not args.quiet:
        _print_report(report)
    if failures:
        print("INVARIANTS FAILED:", file=sys.stderr)
        for line in failures:
            print(f"  - {line}", file=sys.stderr)
        return 1
    if not args.quiet:
        print("invariants: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
