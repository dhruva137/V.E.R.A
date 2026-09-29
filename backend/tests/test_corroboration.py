"""Corroboration: planes, noisy-OR, and flags that never hide an asset."""

from __future__ import annotations

import pytest

from engine.core.corroboration import (
    DEFAULT_FLAG_THRESHOLD,
    Reading,
    corroborate,
    observations_for,
    plane_for,
)


def r(source, plane, confidence, claim="vulnerable", provenance="artifact_parsed"):
    return Reading(source, plane, provenance, confidence, claim)


def test_noisy_or_across_planes():
    result = corroborate([r("tls", "observed", 0.9), r("keystore", "held", 0.8)])
    # 1 - (1 - 0.9)(1 - 0.8) = 0.98
    assert result["confidence"] == pytest.approx(0.98)
    assert result["planes"] == {"held": 0.8, "observed": 0.9}


def test_same_plane_counts_once():
    """Two views of one artefact are not two kinds of evidence."""
    one = corroborate([r("keystore", "held", 0.9)])
    two = corroborate([r("keystore", "held", 0.9), r("certificate", "held", 0.85)])
    assert two["confidence"] == one["confidence"] == pytest.approx(0.9)


def test_confidence_is_capped():
    result = corroborate([
        r("tls", "observed", 0.99), r("ks", "held", 0.99),
        r("cfg", "declared", 0.99), r("src", "built", 0.99),
    ])
    assert result["confidence"] == pytest.approx(0.99)


def test_a_contrary_reading_never_adds_confidence():
    alone = corroborate([r("tls", "observed", 0.9)])
    contested = corroborate([r("tls", "observed", 0.9), r("agent", "declared", 0.35, "safe")])
    assert contested["confidence"] == alone["confidence"]
    assert contested["claim"] == "vulnerable"
    assert contested["disagreement"] is True
    assert contested["flagged"] is True
    assert len(contested["opposing"]) == 1


def test_flag_below_threshold_and_single_weak_reading():
    weak = corroborate([r("src", "built", 0.4, provenance="static_analysis")])
    assert weak["flagged"] and "below" in weak["flag_reason"]

    single = corroborate([r("src", "built", 0.55, provenance="static_analysis")])
    assert single["flagged"] and "second evidence plane" in single["flag_reason"]

    strong = corroborate([r("tls", "observed", 0.98)])
    assert strong["flagged"] is False and strong["flag_reason"] is None


def test_threshold_is_a_parameter():
    reading = [r("cfg", "declared", 0.6), r("src", "built", 0.55)]
    assert corroborate(reading, flag_threshold=0.9)["flagged"] is True
    assert corroborate(reading, flag_threshold=0.1)["flagged"] is False


def test_empty_is_flagged_not_crashed():
    result = corroborate([])
    assert result["flagged"] is True and result["confidence"] == 0.0


def test_plane_mapping():
    assert plane_for("tls") == "observed"
    assert plane_for("vault_pkcs11") == "held"
    assert plane_for("vault_keystore") == "held"
    assert plane_for("config") == "declared"
    assert plane_for("binary_scanner") == "built"
    assert plane_for("", "source") == "built"
    assert plane_for("mystery", "unknown-type") == "declared"


class _Asset:
    def __init__(self, **kw):
        self.source_type = kw.get("source_type", "keystore")
        self.quantum_vulnerable = kw.get("quantum_vulnerable", True)
        self.verdict = kw.get("verdict", "shor")
        self.raw_details = kw.get("raw_details", {})


def test_merged_asset_yields_one_reading_per_sensor():
    asset = _Asset(raw_details={"corroborated_by": ["vault_certificate", "vault_keystore"]})
    readings = observations_for(asset)
    assert {x.source for x in readings} == {"vault_certificate", "vault_keystore"}
    assert all(x.plane == "held" for x in readings)


def test_unresolved_algorithm_is_a_weak_vulnerable_reading():
    asset = _Asset(verdict="unknown", source_type="source",
                   raw_details={"discovered_by": "source"})
    (reading,) = observations_for(asset)
    assert reading.claim == "vulnerable"
    assert reading.confidence < DEFAULT_FLAG_THRESHOLD
    assert reading.plane == "built"
