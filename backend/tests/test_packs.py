"""Sector packs - the plug-in / plug-out layer.

The property that matters is not that a pack adds content. It is that the
product stays correct when a pack is unplugged, because that is the difference
between an agnostic engine and one with nine hardcoded branches.
"""

import pytest

from engine.packs import PACKS, PackRegistry, SectorPack
from engine.profiles import PROFILES


@pytest.fixture
def registry():
    """A fresh registry with everything plugged in."""
    reg = PackRegistry()
    for pack_id in PACKS:
        reg.enable(pack_id)
    return reg


# --------------------------------------------------------------------------
# Content integrity
# --------------------------------------------------------------------------


def test_every_pack_cites_its_sources():
    """A control mapping that cannot name its source is a liability."""
    for pack_id, pack in PACKS.items():
        assert pack.sources, f"{pack_id} cites nothing"
        assert pack.summary.strip(), f"{pack_id} has no summary"
        assert pack.version, f"{pack_id} has no version"


def test_every_control_names_what_answers_it():
    """The whole value is mapping an auditor's question to engine output."""
    for pack_id, pack in PACKS.items():
        for control in pack.controls:
            assert control.answered_by.strip(), f"{pack_id}/{control.id} answers nothing"
            assert control.framework.strip()
            assert control.requirement.strip()


def test_every_milestone_is_sourced():
    """A wrong date is worse than no date."""
    for pack_id, pack in PACKS.items():
        for milestone in pack.milestones:
            assert milestone.source.strip(), f"{pack_id}/{milestone.year} unsourced"
            assert 2024 <= milestone.year <= 2040


def test_pack_sectors_match_real_profiles():
    """A pack aimed at a sector that does not exist can never be applied."""
    for pack_id, pack in PACKS.items():
        if pack.sector == "*":
            continue
        assert pack.sector in PROFILES, f"{pack_id} targets unknown sector {pack.sector}"


def test_control_ids_are_unique_within_a_pack():
    for pack_id, pack in PACKS.items():
        ids = [c.id for c in pack.controls]
        assert len(ids) == len(set(ids)), f"{pack_id} has duplicate control ids"


# --------------------------------------------------------------------------
# Plug in / plug out
# --------------------------------------------------------------------------


def test_a_sector_pack_adds_content_over_baseline(registry):
    payments = registry.resolved("payments")
    baseline_only = PackRegistry().resolved("payments")
    assert len(payments["controls"]) > len(baseline_only["controls"])
    assert "pack.payments" in payments["packs_applied"]


def test_unplugging_a_pack_degrades_to_correct_not_empty(registry):
    """The defining test of agnosticism: with the sector pack removed the
    product must still say something true, not nothing."""
    registry.disable("pack.payments")
    resolved = registry.resolved("payments")

    assert resolved["packs_applied"] == ["pack.baseline"]
    assert resolved["controls"], "unplugging left the product with no controls"
    assert resolved["board_framing"].strip(), "unplugging left no framing"
    assert resolved["milestones"], "the universal deadlines must survive"


def test_the_baseline_pack_cannot_be_unplugged(registry):
    assert registry.disable("pack.baseline") is False
    assert registry.is_enabled("pack.baseline")


def test_baseline_applies_to_every_sector(registry):
    for sector in PROFILES:
        applied = registry.resolved(sector)["packs_applied"]
        assert "pack.baseline" in applied, f"{sector} lost the baseline"


def test_enabling_an_unknown_pack_is_refused(registry):
    assert registry.enable("pack.does-not-exist") is False


def test_toggling_is_idempotent(registry):
    registry.enable("pack.telecom")
    first = registry.resolved("telecom")
    registry.enable("pack.telecom")
    assert registry.resolved("telecom") == first


# --------------------------------------------------------------------------
# Merge behaviour
# --------------------------------------------------------------------------


def test_sector_framing_wins_over_baseline(registry):
    """The specific voice must beat the generic one, or every sector reads the
    same and the pack was pointless."""
    payments = registry.resolved("payments")
    baseline = PACKS["pack.baseline"].board_framing
    assert payments["board_framing"] != baseline
    assert "PCI" in payments["board_framing"]


def test_duplicate_milestones_are_collapsed(registry):
    """Several packs cite the same NIST dates; they must appear once."""
    milestones = registry.resolved("payments")["milestones"]
    keys = [(m["year"], m["label"]) for m in milestones]
    assert len(keys) == len(set(keys))


def test_milestones_are_returned_in_date_order(registry):
    for sector in ("payments", "government", "telecom"):
        years = [m["year"] for m in registry.resolved(sector)["milestones"]]
        assert years == sorted(years), f"{sector} milestones out of order"


def test_binding_milestones_are_marked(registry):
    """An advisory date and a statutory one must not look alike."""
    government = registry.resolved("government")
    binding = [m for m in government["milestones"] if m["binding"]]
    assert binding, "government has no binding milestones, which cannot be right"


def test_every_sector_resolves_without_error(registry):
    for sector in PROFILES:
        resolved = registry.resolved(sector)
        assert resolved["sector"] == sector
        assert resolved["controls"]
        assert resolved["sources"]


def test_insurance_questions_are_present_for_every_sector(registry):
    """Cyber insurers now ask about quantum readiness at renewal; a sector with
    no answer prepared is a sector we cannot sell into."""
    for sector in PROFILES:
        assert registry.resolved(sector)["insurance_questions"]
