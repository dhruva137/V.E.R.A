"""Per-primitive threat horizon and the versioned threat model.

WHY
---
A P-256 key and an RSA-2048 key are both "Shor-vulnerable", but breaking them
takes different quantum computers: the best published estimates are 1,193
logical qubits for P-256 and 1,409 for RSA-2048. One arrival date for both is
wrong in a way that matters for ordering. So each primitive's survival curve
is the reference curve shifted in time:

    delta_p = D * log2(L_p / L_ref)        years; negative = arrives earlier
    S_p(t)  = S_ref(t - delta_p)

L are logical-qubit estimates (`kb/quantum_resources.yaml`, each row cited),
L_ref is RSA-2048, and D is the assumed doubling time of logical-qubit
capacity. D is a stated assumption (default 2.0 years), not a measurement; the
UI shows it and lets the operator change it. A row without a verified estimate
gets delta = 0 and says so.

VERSIONS
--------
`kb/threat_model_versions.json` records each threat-model version: the GRI
edition, D, a hash of the resources table and a changelog entry. The resources
table's hash must match the current version's; a changed table without a new
version fails the test suite, so a score can never move for an unexplained
reason. `VERA_THREAT_MODEL` pins a version.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
from functools import lru_cache
from pathlib import Path

import yaml

KB = Path(__file__).resolve().parent / "kb"
RESOURCES_PATH = KB / "quantum_resources.yaml"
VERSIONS_PATH = KB / "threat_model_versions.json"
DEFAULT_DOUBLING_YEARS = 2.0          # default 2.0; overridable


@lru_cache(maxsize=1)
def resources() -> dict:
    return yaml.safe_load(RESOURCES_PATH.read_text(encoding="utf-8"))


def table_hash() -> str:
    """SHA-256 over the rows that determine a shift (numbers and matching keys)."""
    rows = [{k: row.get(k) for k in ("id", "algorithms", "curves", "key_sizes", "logical_qubits")}
            for row in resources()["rows"]]
    blob = json.dumps({"reference": resources()["reference"], "rows": rows}, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()


@lru_cache(maxsize=1)
def versions() -> list[dict]:
    return json.loads(VERSIONS_PATH.read_text(encoding="utf-8"))["versions"]


def current_version() -> dict:
    """The pinned version (`VERA_THREAT_MODEL`) or the latest one."""
    pinned = os.environ.get("VERA_THREAT_MODEL", "").strip()
    all_versions = versions()
    if pinned:
        for version in all_versions:
            if version["version"] == pinned:
                return version
        raise ValueError(f"VERA_THREAT_MODEL={pinned!r} is not a known threat-model version")
    return all_versions[-1]


def doubling_years() -> float:
    override = os.environ.get("VERA_QUBIT_DOUBLING_YEARS", "").strip()
    return float(override) if override else float(current_version().get("D", DEFAULT_DOUBLING_YEARS))


def shift_years(logical_qubits: float, reference_qubits: float, doubling: float) -> float:
    """delta = D * log2(L_p / L_ref). Monotone in L_p; zero when D = 0 or L_p = L_ref."""
    return doubling * math.log2(logical_qubits / reference_qubits)


def _canonical_curve(curve: str | None) -> str:
    return (curve or "").replace("_", "-").lower()


def row_for(algorithm: str | None, key_size: int | None = None, curve: str | None = None) -> dict | None:
    """The resources row for a primitive, or None if it is not Shor-relevant here."""
    if not algorithm:
        return None
    alg = algorithm.upper()
    base = alg.split("-")[0]
    curve_key = _canonical_curve(curve)
    candidates = [r for r in resources()["rows"] if any(a.upper() in (alg, base) for a in r.get("algorithms", []))]
    if curve_key:
        for row in candidates:
            if any(_canonical_curve(c) == curve_key for c in row.get("curves", [])):
                return row
    if key_size:
        for row in candidates:
            if key_size in row.get("key_sizes", []):
                return row
    unsized = [r for r in candidates if not r.get("key_sizes") and not r.get("curves")]
    if unsized:
        return unsized[0]
    if base == "RSA" and key_size is None:
        return next(r for r in resources()["rows"] if r["id"] == resources()["reference"])
    return None


def shift_for(algorithm: str | None, key_size: int | None = None, curve: str | None = None,
              doubling: float | None = None) -> dict:
    """{delta_years, basis, row} for one primitive. delta = 0 whenever the row is not verified."""
    d = doubling_years() if doubling is None else float(doubling)
    ref = next(r for r in resources()["rows"] if r["id"] == resources()["reference"])
    row = row_for(algorithm, key_size, curve)
    if row is None:
        return {"delta_years": 0.0, "basis": "No resources row for this primitive; reference curve used.",
                "row": None, "doubling_years": d}
    if not row.get("logical_qubits") or row.get("status") != "verified":
        return {"delta_years": 0.0, "basis": f"{row['label']}: {row.get('note', 'no verified estimate')}",
                "row": _public(row), "doubling_years": d}
    delta = shift_years(row["logical_qubits"], ref["logical_qubits"], d)
    direction = "earlier" if delta < 0 else "later" if delta > 0 else "same as reference"
    return {
        "delta_years": round(delta, 3),
        "basis": (f"{row['label']}: {row['logical_qubits']:,} logical qubits vs {ref['logical_qubits']:,} for "
                  f"{ref['label']} -> {abs(delta):.2f} yr {direction} at D = {d:g} yr."),
        "row": _public(row), "doubling_years": d,
    }


def _public(row: dict) -> dict:
    return {k: row.get(k) for k in ("id", "label", "logical_qubits", "physical_qubits", "source", "url", "date",
                                    "status", "note")}


def describe() -> dict:
    """Everything `/api/threat-model` shows about resources and versions."""
    version = current_version()
    return {
        "version": version,
        "versions": versions(),
        "table_hash": table_hash(),
        "table_matches_version": table_hash() == version["resources_table_hash"],
        "doubling_years": doubling_years(),
        "reference": resources()["reference"],
        "verified_on": resources().get("verified_on"),
        "rows": [dict(_public(r), shift=shift_for(r["algorithms"][0],
                                                  (r.get("key_sizes") or [None])[0],
                                                  (r.get("curves") or [None])[0])["delta_years"])
                 for r in resources()["rows"]],
    }
