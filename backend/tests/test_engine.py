"""Smoke tests for the claims VERA makes on stage.

These are deliberately written against the *arguments*, not just the code: if
the survival curve stops being monotone, if the CBOM stops validating, or if
the ordering-invariance claim stops holding, the demo is making a false claim
and a test should say so before a judge does.

Run with:  python -m pytest backend/tests -q
"""

from __future__ import annotations

import datetime

import numpy as np
import pytest

from collectors.demo_estate import generate_estate
from engine import taxonomy
from engine.cbom import generate_cbom
from engine.cbom_validate import validate_cbom
from engine.qirs import (
    assign_risk_level, compute_hndl, compute_qirs_band, compute_tnfl, order_assets, score_assets,
)
from engine.regulatory import compute_slack, governing_persona, map_regulatory
from engine.sensitivity import analyse_invariance
from engine.threat_model import ThreatModel, survival_families
from models.schemas import CryptoAsset


@pytest.fixture(scope="module")
def model():
    return ThreatModel()


@pytest.fixture(scope="module")
def estate(model):
    assets = [
        CryptoAsset(**finding.model_dump(), name=finding.source_location)
        for finding in generate_estate()
    ]
    assets = score_assets(assets, model)
    assets = map_regulatory(assets, org_persona="Banking")
    for asset in assets:
        asset.risk_level = assign_risk_level(asset)
    return order_assets(assets, model)


# --------------------------------------------------------------------------
# Threat model
# --------------------------------------------------------------------------


def test_survival_is_monotone_non_increasing(model):
    """A survival function cannot increase. The original code's optimistic curve
    went from 0.66 at t=5 to 0.72 at t=10, which is not a survival function."""
    for index in range(3):
        values = [model.survival(float(t))[index] for t in np.linspace(0, 60, 1200)]
        assert all(b <= a + 1e-9 for a, b in zip(values, values[1:])), (
            f"ensemble member {index} is not monotone non-increasing"
        )


def test_ensemble_members_stay_ordered(model):
    """Optimistic survival must never fall below pessimistic, or the reported
    band inverts and the low end of the risk range exceeds the high end."""
    for t in np.linspace(0, 60, 400):
        optimistic, median, pessimistic = model.survival(float(t))
        assert pessimistic <= median <= optimistic + 1e-9


def test_curve_reproduces_elicited_anchors(model):
    """The interpolant passes through the published GRI figures exactly, rather
    than smoothing over them."""
    assert model.survival(5.0)[1] == pytest.approx(1 - 0.34, abs=1e-6)
    assert model.survival(10.0)[1] == pytest.approx(1 - 0.385, abs=1e-6)
    assert model.survival(15.0)[1] == pytest.approx(1 - 0.62, abs=1e-6)


def test_band_is_not_degenerate(model):
    """The band is the headline honesty claim; if optimistic and pessimistic
    collapse onto each other it is decoration."""
    optimistic, _, pessimistic = model.survival(10.0)
    assert optimistic - pessimistic > 0.15


# --------------------------------------------------------------------------
# Taxonomy
# --------------------------------------------------------------------------


def test_aes_bulk_cipher_is_not_shor_breakable():
    """The original bug: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384' contains the
    substring 'RSA', so the whole suite including its AES record layer was
    reported as breakable by Shor."""
    breakdown = taxonomy.decompose_cipher_suite("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")
    bulk = [f for role, f in breakdown.components if role == "suite_bulk_cipher"]
    assert bulk and bulk[0].verdict == taxonomy.PQC


def test_tls13_suite_carries_no_key_exchange():
    """TLS 1.3 suite names do not name a key exchange. Inferring one is wrong."""
    breakdown = taxonomy.decompose_cipher_suite("TLS_AES_256_GCM_SHA384")
    assert breakdown.key_exchange is None
    assert breakdown.authentication is None


def test_broken_hashes_are_reported_not_ignored():
    """SHA-1 and MD5 are not Shor-vulnerable, which the original code turned
    into 'not vulnerable' and therefore silence."""
    for name in ("SHA-1", "MD5"):
        result = taxonomy.classify_finding(name, None, None, None, None)
        assert result["verdict"] == taxonomy.CLASSICAL
        assert result["classically_broken"] is True


def test_protocol_version_does_not_dominate_verdict():
    """TLS 1.3 is not a weakness; the group it negotiates is, and that is a
    separate asset. Folding one into the other re-inflates the vulnerable count."""
    result = taxonomy.classify_finding(None, None, "TLS_AES_256_GCM_SHA384", None, "TLSv1.3")
    assert result["quantum_vulnerable"] is False


def test_deprecated_protocol_is_a_finding():
    assert taxonomy.classify_protocol("TLSv1.0")[0] == taxonomy.CLASSICAL
    assert taxonomy.classify_protocol("TLSv1")[0] == taxonomy.CLASSICAL
    assert taxonomy.classify_protocol("SSLv3")[0] == taxonomy.CLASSICAL
    # And a current version must not be swept up by a prefix match.
    assert taxonomy.classify_protocol("TLSv1.2")[0] == taxonomy.PQC


def test_asset_can_be_both_broken_and_shor_vulnerable():
    """3DES over ECDHE is both. Reporting only the governing verdict would drop
    one of the two counts."""
    result = taxonomy.classify_finding(
        None, None, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", None, "TLSv1.2"
    )
    assert result["classically_broken"] is True
    assert result["quantum_vulnerable"] is True


# --------------------------------------------------------------------------
# QIRS
# --------------------------------------------------------------------------


def test_hndl_is_additive_and_tnfl_saturates(model):
    """The core technical claim: confidentiality risk grows without bound in
    migration time, integrity risk is capped by it."""
    def build(y: float) -> CryptoAsset:
        asset = CryptoAsset(
            id="t", source_type="keystore", source_location="/k", name="k",
            quantum_vulnerable=True, vulnerability_reason="",
        )
        asset.x_c, asset.x_i, asset.y = 5.0, 2.0, y
        asset.s, asset.e, asset.c = 1.0, 1.0, 1.0
        return asset

    slow, slower = build(1.0), build(8.0)

    # HNDL keeps rising as migration slips.
    assert compute_hndl(slower, model) > compute_hndl(slow, model)

    # TNFL saturates: once Y exceeds X_i the horizon is pinned at X_i.
    assert compute_tnfl(slower, model) == pytest.approx(compute_tnfl(build(2.0), model))


def test_quantum_safe_assets_score_zero(model):
    asset = CryptoAsset(
        id="s", source_type="keystore", source_location="/k", name="k",
        quantum_vulnerable=False, vulnerability_reason="",
    )
    asset.x_c, asset.x_i, asset.y, asset.s, asset.e, asset.c = 9, 9, 1, 1, 1, 1
    assert compute_hndl(asset, model) == 0.0
    assert compute_tnfl(asset, model) == 0.0


def test_band_brackets_the_point_estimate(model, estate):
    for asset in estate:
        if asset.quantum_vulnerable:
            low, high = compute_qirs_band(asset, model)
            assert low <= asset.qirs <= high + 1e-9


def test_classically_broken_assets_stay_out_of_the_pqc_backlog(estate):
    """A 3DES PIN-translation key is urgent, but replacing it is classical
    hygiene rather than a PQC migration. Mixing the two produces a backlog
    nobody can action."""
    vulnerable_ranks = [a.priority_rank for a in estate if a.quantum_vulnerable]
    non_pqc_ranks = [a.priority_rank for a in estate if not a.quantum_vulnerable]
    assert max(vulnerable_ranks) < min(non_pqc_ranks)


# --------------------------------------------------------------------------
# Regulatory
# --------------------------------------------------------------------------


def test_highest_risk_persona_governs():
    assert governing_persona("Banking", "CII") == "CII"
    assert governing_persona("Banking", None) == "Banking"
    assert governing_persona("General Enterprise", "Technology Provider") == "Technology Provider"


def test_slack_matches_the_blueprint_demo_case():
    """Blueprint section 9: a code-signing key under the CII high-priority
    milestone with a two-year migration shows slack = -7 months, as of the
    August 2026 demo date."""
    august_2026 = datetime.datetime(2026, 8, 6)
    assert compute_slack(2028, 2.0, now=august_2026) == pytest.approx(-7.0, abs=0.3)


def test_org_baseline_is_never_diluted_by_an_asset(estate):
    """Every asset must sit at the org baseline or stricter. The original code
    classified persona from file paths, so keystores fell to General Enterprise
    and got 2033 deadlines inside a bank."""
    assert all(asset.persona in {"Banking", "CII"} for asset in estate)


def test_negative_slack_exists_and_is_signing_dominated(estate):
    behind = [a for a in estate if a.slack_months < 0]
    assert behind, "the demo needs assets that are genuinely behind schedule"
    worst = min(behind, key=lambda a: a.slack_months)
    assert worst.y >= 2.0, "the worst overruns should be long-migration anchors"


# --------------------------------------------------------------------------
# CBOM
# --------------------------------------------------------------------------


def test_cbom_validates(estate):
    report = validate_cbom(generate_cbom(estate, org_name="test"))
    failures = [check for check in report["checks"] if not check["passed"]]
    assert report["valid"], f"CBOM failed validation: {failures}"


def test_validator_is_not_vacuous():
    """A validator that passes everything proves nothing. This is the shape the
    original emitter produced."""
    broken = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "not-a-urn",
        "version": 1,
        "metadata": {"timestamp": "yesterday"},
        "components": [
            {
                "type": "cryptographic-asset",
                "bom-ref": "dup",
                "name": "x",
                "cryptoProperties": {
                    "assetType": "protocol",
                    # Wrong property object for the assetType, and a
                    # cryptoFunction that is not in the 1.6 enum.
                    "algorithmProperties": {
                        "primitive": "pke", "cryptoFunctions": ["signing"],
                    },
                },
            },
            {"type": "cryptographic-asset", "bom-ref": "dup", "name": "y",
             "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {}}},
        ],
    }
    report = validate_cbom(broken)
    assert not report["valid"]
    failed = {check["id"] for check in report["checks"] if not check["passed"]}
    assert {"envelope", "metadata", "bomref_unique", "property_object", "crypto_functions"} <= failed


def test_cbom_dependency_refs_all_resolve(estate):
    cbom = generate_cbom(estate, org_name="test")
    refs = {component["bom-ref"] for component in cbom["components"]}
    for dependency in cbom["dependencies"]:
        assert dependency["ref"] in refs
        for target in dependency.get("dependsOn", []):
            assert target in refs


# --------------------------------------------------------------------------
# Ordering invariance - blueprint Claim 2
# --------------------------------------------------------------------------


def test_within_axis_ordering_is_invariant_for_equal_sensitivity(estate):
    """The theorem, in its true conditional form. Ranking by H is ranking by
    X_c + Y only for assets with equal S.E."""
    result = analyse_invariance(estate)
    assert result["summary"]["min_rho_hndl_stratified"] == pytest.approx(1.0, abs=1e-9)
    assert result["summary"]["min_rho_tnfl_stratified"] == pytest.approx(1.0, abs=1e-9)


def test_unconditional_invariance_claim_is_false(estate):
    """The blueprint states Claim 2 without the equal-S.E condition. That
    version does not hold, and the tool must not rely on it - this test exists
    so nobody 'fixes' the honest reporting back into the overclaim."""
    result = analyse_invariance(estate)
    assert result["summary"]["min_rho_hndl_global"] < 1.0


def test_survival_families_are_all_monotone():
    """The invariance argument requires monotone survival functions. A
    non-monotone family would make the test vacuous."""
    for name, family in survival_families().items():
        values = [family["fn"](float(t)) for t in np.linspace(0, 45, 500)]
        assert all(b <= a + 1e-9 for a, b in zip(values, values[1:])), f"{name} is not monotone"
        assert family["fn"](0.0) == pytest.approx(1.0, abs=1e-6)


# --------------------------------------------------------------------------
# Estate
# --------------------------------------------------------------------------


def test_estate_is_deterministic():
    """A demo whose headline count changes between runs is unusable."""
    first = [f.id for f in generate_estate()]
    second = [f.id for f in generate_estate()]
    assert first == second


def test_estate_separates_the_two_axes(estate):
    """The dual-axis argument needs assets at both extremes. If the estate has
    no high-TNFL/low-HNDL population, the heatmap proves nothing."""
    vulnerable = [a for a in estate if a.quantum_vulnerable]
    top_hndl = max(vulnerable, key=lambda a: a.h_score)
    top_tnfl = max(vulnerable, key=lambda a: a.t_score)
    assert top_hndl.id != top_tnfl.id
    assert top_hndl.t_score < 0.05, "the top HNDL asset should have near-zero integrity risk"
    assert top_tnfl.h_score < top_tnfl.t_score


# --------------------------------------------------------------------------
# CBOM round trip
#
# The documentation says a CBOM imported from another tool "is scored by exactly
# the same code as a live TLS handshake". That is true of the code and was not
# true of the result: exporting this estate and importing it back re-derived a
# materially softer picture, because a CycloneDX component names an algorithm
# and nothing else - not the host it runs on, not the tags the persona is
# derived from, not which of three fields the primitive lived in.
# --------------------------------------------------------------------------


def _round_trip(assets):
    """Export to CBOM, import, and re-run the same pipeline the API runs."""
    from api.routes import process_findings, state
    from engine.cbom_import import cbom_to_findings

    document = generate_cbom(assets)
    findings = cbom_to_findings(document)
    previous = state.assets
    try:
        result = process_findings(
            findings, duration=0.0, kind="cbom", label="round trip",
            org_persona="Banking",
        )
        return list(state.assets), result
    finally:
        state.assets = previous


@pytest.fixture(scope="module")
def scanned_estate():
    from api.routes import run_demo_scan, state
    run_demo_scan(org_persona="Banking")
    return list(state.assets)


def test_a_round_tripped_estate_keeps_its_headline_numbers(scanned_estate):
    """195 / 173 / 15 and the QIRS band are what the documentation quotes."""
    imported, _ = _round_trip(scanned_estate)

    def headline(assets):
        return (
            len(assets),
            sum(1 for a in assets if a.quantum_vulnerable),
            sum(1 for a in assets if a.slack_months < 0),
            round(max(a.qirs for a in assets), 4),
            round(sum(a.qirs for a in assets) / len(assets), 4),
        )

    assert headline(imported) == headline(scanned_estate)


def test_a_round_tripped_estate_keeps_its_personas_and_classes(scanned_estate):
    """Persona drives the statutory deadline, and it is derived from tags and
    location - neither of which CycloneDX has a field for. Without them the CII
    population fell from 55 assets to 14 and the deadlines moved out by years."""
    import collections

    imported, _ = _round_trip(scanned_estate)
    for attribute in ("persona", "asset_class", "name"):
        assert (
            collections.Counter(getattr(a, attribute) for a in imported)
            == collections.Counter(getattr(a, attribute) for a in scanned_estate)
        ), attribute


def test_a_round_tripped_estate_still_validates_as_cyclonedx(scanned_estate):
    """The extra `vera:` properties must not cost a single rule, the official schema included."""
    document = generate_cbom(scanned_estate)
    report = validate_cbom(document)
    assert report["valid"] is True
    assert report["rules_passed"] == report["rules_total"] == 17
    assert next(c for c in report["checks"] if c["id"] == "official_schema")["passed"]
