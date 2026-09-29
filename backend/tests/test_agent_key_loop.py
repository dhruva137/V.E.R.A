"""The agent's key loop: scan -> inspect -> preview -> migrate -> verify.

This is the workflow the product is judged on, so it is tested as a workflow
rather than as five independent tools. The properties that matter:

* a key that cannot be migrated says so, and says why, before anyone acts on it
* verification reads the estate back and can actually fail
* the system prompt does not claim a sensor is active that the registry calls a
  blind spot — the failure mode that costs credibility in front of a reviewer
"""

from __future__ import annotations

import pytest

from engine import agent
from engine.agent_control import get_control


@pytest.fixture
def vault_estate():
    """A loaded vault estate, with the control plane left autonomous.

    Restores both the estate and the control mode afterwards so these tests
    cannot leak state into the rest of the suite.
    """
    from api.routes import state

    control = get_control()
    previous_mode = control.settings.mode
    previous_limit = control.settings.max_tool_calls_per_minute
    previous_assets = list(state.assets)

    # A test file makes far more tool calls per minute than a human turn does,
    # so the default 20/min limit would exhaust partway through and fail later
    # tests for the wrong reason. The limiter itself is covered in
    # test_agent_control.py; here it is deliberately taken out of the way.
    control.settings.max_tool_calls_per_minute = 240
    control.reset()

    # scan_key_vault is a write tool; approval mode would only propose. Load
    # the estate under autonomous so the fixture actually applies.
    control.settings.mode = "autonomous"
    agent.execute_tool("scan_key_vault", {"merge": False})
    yield state

    control.settings.mode = previous_mode
    control.settings.max_tool_calls_per_minute = previous_limit
    control.reset()
    state.assets = previous_assets


def _worst(asset_class=None):
    result = agent.execute_tool("list_assets", {"sort_by": "qirs", "limit": 40})
    rows = result["assets"]
    if asset_class:
        rows = [r for r in rows if r["asset_class"] == asset_class]
    return rows[0]


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def test_key_loop_tools_are_registered():
    names = {t["function"]["name"] for t in agent.TOOLS_SCHEMA}
    assert {"scan_key_vault", "inspect_key", "verify_migration"} <= names
    for name in ("scan_key_vault", "inspect_key", "verify_migration"):
        assert name in agent.TOOL_IMPLEMENTATIONS


def test_key_loop_tools_are_reads_not_writes():
    """Inspect/verify must never be gated; vault scan mutates the estate."""
    from engine.agent_control import WRITE_TOOLS

    assert "scan_key_vault" in WRITE_TOOLS
    assert "inspect_key" not in WRITE_TOOLS
    assert "verify_migration" not in WRITE_TOOLS


# ---------------------------------------------------------------------------
# Scan and inspect
# ---------------------------------------------------------------------------

def test_scan_key_vault_loads_the_estate(vault_estate):
    result = agent.execute_tool("scan_key_vault", {"merge": False})
    assert result["ingested"] > 0
    assert result["cbom_valid"] is True
    assert result["sources_unmeasured"] == []


def test_scan_key_vault_reports_unmeasured_sources(tmp_path):
    """A vault with nothing in it is an error with a remedy, not a silent zero."""
    control = get_control()
    previous = control.settings.mode
    control.settings.mode = "autonomous"
    try:
        result = agent.execute_tool("scan_key_vault", {"vault_root": str(tmp_path)})
    finally:
        control.settings.mode = previous
    assert "error" in result
    assert "remedy" in result


def test_inspect_key_reports_custody_and_never_key_material(vault_estate):
    top = _worst()
    detail = agent.execute_tool("inspect_key", {"asset_id": top["id"]})
    assert detail["custody"]["location"]
    assert detail["custody"]["provenance"]
    # The safety claim, asserted at the tool boundary as well as the collector.
    blob = str(detail)
    assert "BEGIN PRIVATE KEY" not in blob
    assert "CKA_VALUE" not in blob


def test_inspect_key_flags_a_key_that_cannot_be_migrated(vault_estate):
    """The single most valuable thing this tool says."""
    hsm = next(
        a for a in vault_estate.assets
        if a.raw_details.get("discovered_by") == "vault_pkcs11"
    )
    detail = agent.execute_tool("inspect_key", {"asset_id": hsm.id})
    assert detail["changeability"]["change_blocked"] is True
    assert detail["changeability"]["actionable_today"] is False
    assert detail["changeability"]["reason"], "a block must state its reason"
    assert "cannot be migrated in place" in detail["guidance"]


def test_inspect_key_rejects_an_unknown_id(vault_estate):
    result = agent.execute_tool("inspect_key", {"asset_id": "no-such-key"})
    assert "error" in result
    assert "remedy" in result


# ---------------------------------------------------------------------------
# Migrate and verify
# ---------------------------------------------------------------------------

def test_full_loop_migrates_and_verifies(vault_estate):
    target = _worst(asset_class="root_ca")

    preview = agent.execute_tool("preview_migration", {"asset_id": target["id"]})
    assert preview["assets_affected"] == 1

    migration = agent.execute_tool(
        "migrate_asset", {"asset_id": target["id"], "strategy": "hybrid"}
    )
    assert migration["migrated"] == 1

    verified = agent.execute_tool("verify_migration", {"asset_id": target["id"]})
    assert verified["verified"] is True
    assert verified["checks_failed"] == 0
    names = {c["check"] for c in verified["checks"]}
    assert {
        "algorithm_replaced", "no_longer_quantum_vulnerable",
        "chain_not_orphaned", "cbom_still_valid", "checks_passed",
    } <= names


def test_verify_fails_on_an_asset_that_was_never_migrated(vault_estate):
    """Verification must be able to fail, or it is decoration."""
    untouched = next(a for a in vault_estate.assets if not a.migrated)
    verified = agent.execute_tool("verify_migration", {"asset_id": untouched.id})
    assert verified["verified"] is False
    assert verified["checks_failed"] > 0
    failed = {c["check"] for c in verified["checks"] if not c["passed"]}
    assert "algorithm_replaced" in failed


def test_verify_reports_downstream_as_follow_up_not_as_failure(vault_estate):
    """Migrating an anchor leaves children to be re-issued. That is the next
    step, not a failed migration, and conflating them would be wrong."""
    target = _worst(asset_class="root_ca")
    agent.execute_tool("migrate_asset", {"asset_id": target["id"], "strategy": "hybrid"})
    verified = agent.execute_tool("verify_migration", {"asset_id": target["id"]})

    assert verified["verified"] is True
    follow_up = verified["follow_up"]
    assert follow_up["dependents_still_vulnerable"] > 0
    assert "not a failure" in follow_up["note"]


def test_verify_checks_estate_invariants_even_without_an_asset(vault_estate):
    verified = agent.execute_tool("verify_migration", {})
    names = {c["check"] for c in verified["checks"]}
    assert "cbom_still_valid" in names
    assert "checks_passed" in names


# ---------------------------------------------------------------------------
# The honesty guard
# ---------------------------------------------------------------------------

def test_system_prompt_does_not_claim_unconfigured_sensors_are_active():
    """Regression guard.

    A previous build hardcoded 'eBPF Kernel Tracer (active)' and a table of
    invented confidence percentages into the prompt, while the discovery
    registry correctly reported those same connectors as blind spots. The agent
    contradicted the product, which is the one thing that cannot happen in front
    of someone who checks.
    """
    prompt = agent.SYSTEM_PROMPT
    assert "eBPF Kernel Tracer (active)" not in prompt
    assert "Runtime TLS = 95%" not in prompt
    # And it must still tell the model where the truth lives.
    assert "get_connector_status" in prompt


def test_no_tool_description_names_a_sensor_that_does_not_exist():
    """The prompt was fixed once and the tool *descriptions* still named the
    invented connectors, which reaches the model just as directly.

    A tool description may not name a sensor the registry has never heard of.
    """
    from engine.discovery import surface

    known = {p["id"] for p in surface()["plugins"]}
    known |= {p["name"] for p in surface()["plugins"]}
    invented = [
        "eBPF Kernel Tracer", "K8s Istio/Envoy Mesh", "Istio",
        "External Partner API Gateway", "F5/AWS ALB",
    ]
    for tool in agent.TOOLS_SCHEMA:
        description = tool["function"]["description"]
        for name in invented:
            assert name not in description or name in known, (
                f"{tool['function']['name']} names '{name}', which the discovery "
                f"registry does not define"
            )


def test_prompt_confidence_claims_match_the_provenance_table():
    """No confidence figure may appear in the prompt that the table does not
    define — the numbers must have one source."""
    import re

    from engine.plugins import PROVENANCE

    allowed = {int(v["confidence"] * 100) for v in PROVENANCE.values()}
    for match in re.findall(r"(\d{2})%", agent.SYSTEM_PROMPT):
        assert int(match) in allowed, (
            f"{match}% appears in the system prompt but is not a provenance grade"
        )
