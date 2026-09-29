"""The scan pipeline: every asset ranked, checks reported, runs reproducible."""

from __future__ import annotations

from collectors.vault_collector import scan_vault
from engine import mosca
from engine.core import scan_pipeline
from engine.qirs import assign_risk_level, order_assets, score_assets
from engine.regulatory import map_regulatory
from engine.threat_model import ThreatModel
from models.schemas import CryptoAsset


def _estate():
    findings, _ = scan_vault()
    model = ThreatModel()
    assets = [CryptoAsset(**f.model_dump(), name=f.id) for f in findings]
    assets = score_assets(assets, model)
    assets = map_regulatory(assets, org_persona="Banking")
    for asset in assets:
        asset.risk_level = assign_risk_level(asset)
    return order_assets(assets, model)


def test_every_asset_is_ranked_and_flags_never_hide():
    estate = _estate()
    run = scan_pipeline.run(estate)
    assert len(run.ranked) == len(estate)
    assert [r["rank"] for r in run.ranked] == list(range(1, len(estate) + 1))
    ranked_ids = {r["id"] for r in run.ranked}
    assert {r["id"] for r in run.flagged} <= ranked_ids


def test_stages_and_checks():
    run = scan_pipeline.run(_estate())
    assert set(run.trace.stage_timings) == set(scan_pipeline.STAGES)
    assert run.checks_passed is True
    assert {c["key"] for c in run.checks} >= {
        "conservation", "band_contains_score", "ranks_unique",
        "no_key_material", "flags_never_hide",
    }


def test_order_is_mosca_category_then_margin_then_qirs():
    run = scan_pipeline.run(_estate())
    vulnerable = [r for r in run.ranked if r["quantum_vulnerable"]]
    keys = [(mosca.category_rank(r["mosca_category"]), -(r["mosca_margin_years"] or float("-inf")), -r["qirs"])
            for r in vulnerable]
    assert keys == sorted(keys)
    # Quantum-vulnerable work precedes everything else.
    first_other = next((i for i, r in enumerate(run.ranked) if not r["quantum_vulnerable"]), None)
    if first_other is not None:
        assert all(not r["quantum_vulnerable"] for r in run.ranked[first_other:])


def test_malformed_input_is_quarantined_with_a_reason():
    estate = _estate()
    bad = estate[0].model_copy()
    bad.qirs = 7.0
    run = scan_pipeline.run(estate[1:] + [bad, estate[1]])
    reasons = {q["reason"] for q in run.quarantined}
    assert any("outside" in r for r in reasons)
    assert "Duplicate id." in reasons
    assert run.stats["quarantined"] == 2
    assert next(c for c in run.checks if c["key"] == "conservation")["passed"]


def test_leaked_key_field_fails_the_check_but_never_hides_the_ranking():
    estate = _estate()
    estate[0].raw_details = {**estate[0].raw_details, "private_key_pem": "x"}
    run = scan_pipeline.run(estate)
    check = next(c for c in run.checks if c["key"] == "no_key_material")
    assert check["passed"] is False
    assert run.checks_passed is False
    assert len(run.ranked) == len(estate)


def test_ranking_is_deterministic_and_digest_reproducible():
    a = scan_pipeline.run(_estate())
    b = scan_pipeline.run(_estate())
    assert [r["id"] for r in a.ranked] == [r["id"] for r in b.ranked]
    assert a.manifest["digest_sha256"] == b.manifest["digest_sha256"]


def test_order_assets_sets_mosca_fields_and_priority_rank():
    estate = _estate()
    ranks = sorted(a.priority_rank for a in estate)
    assert ranks == list(range(1, len(estate) + 1))
    for asset in estate:
        if asset.quantum_vulnerable:
            assert asset.mosca_category in mosca.CATEGORIES
            assert asset.mosca_axis in {"confidentiality", "integrity"}
        else:
            assert asset.mosca_category == "not_applicable"
