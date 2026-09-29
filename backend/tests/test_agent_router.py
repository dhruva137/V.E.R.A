"""The deterministic intent router (engine.agent_router).

The router's promise is narrow: when the verb names the tool, pick that tool
and the asset the sentence names, and never guess between assets. These tests
pin both halves on a small synthetic estate, with no model and no scan.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from engine import agent_router
from engine.agent_router import route, route_conversation


def _asset(id_, name, location, system, rank, algorithm="RSA"):
    return SimpleNamespace(id=id_, name=name, source_location=location, raw_details={"system": system},
                           algorithm=algorithm, asset_class="signing_key", priority_rank=rank)


ASSETS = [
    _asset("aa11bb22-0001", "RSA in payments-gateway.jar", "tejomaya/pay:4.2!/app/payments-gateway.jar",
           "payments-gateway", 3),
    _asset("aa11bb22-0002", "Embedded EC private key in signing.key", "tejomaya/pay:4.2!/app/config/signing.key",
           "payments-gateway", 2, "ECDSA"),
    _asset("cc33dd44-0003", "RSA via KeyPairGenerator.getInstance (CardVault.java:17)",
           "demo/repos/payments-gateway/src/CardVault.java:17", "payments-gateway", 5),
    _asset("cc33dd44-0004", "RSA via Signature.getInstance (CardVault.java:23)",
           "demo/repos/payments-gateway/src/CardVault.java:23", "payments-gateway", 9),
    _asset("ee55ff66-0005", "ECDSA via EcdsaKeyPair::from_pkcs8 (lib.rs:10)", "demo/repos/portal/src/lib.rs:10",
           "customer-portal", 1, "ECDSA"),
    _asset("ee55ff66-0006", "OpenSSL 1.1.1w in ledgerd", "tejomaya/ledger:12!/usr/local/bin/ledgerd", "core-ledger",
           33, "OpenSSL"),
]


# --------------------------------------------------------------------------
# Tool selection
# --------------------------------------------------------------------------


@pytest.mark.parametrize("text, tool, arguments", [
    ("migrate RSA in payments-gateway.jar", "migrate_asset", {"asset_id": "aa11bb22-0001", "strategy": "hybrid"}),
    ("Please migrate signing.key to hybrid", "migrate_asset", {"asset_id": "aa11bb22-0002", "strategy": "hybrid"}),
    ("migrate signing.key pqc-only", "migrate_asset", {"asset_id": "aa11bb22-0002", "strategy": "pqc_only"}),
    ("upgrade ledgerd to ML-KEM", "migrate_asset", {"asset_id": "ee55ff66-0006", "strategy": "hybrid"}),
    ("preview migrating signing.key", "preview_migration", {"asset_id": "aa11bb22-0002"}),
    ("why is RSA in payments-gateway.jar ranked so high?", "explain_asset", {"asset_id": "aa11bb22-0001"}),
    ("explain the top asset", "explain_asset", {"asset_id": "ee55ff66-0005"}),
    ("why is rank 3 ranked there", "explain_asset", {"asset_id": "aa11bb22-0001"}),
    ("can you explain asset aa11bb22-0002?", "explain_asset", {"asset_id": "aa11bb22-0002"}),
    ("explain the mosca reading for signing.key", "explain_mosca", {"asset_id": "aa11bb22-0002"}),
    ("when does ledgerd become vulnerable", "explain_mosca", {"asset_id": "ee55ff66-0006"}),
    ("how sure are you about signing.key", "explain_evidence", {"asset_id": "aa11bb22-0002"}),
    ("recommend a replacement for lib.rs under cnsa", "recommend", {"asset_id": "ee55ff66-0005", "profile": "cnsa"}),
    ("how many assets are there?", "get_estate_summary", {}),
    ("what is blocked on vendors", "list_vendor_gated", {}),
    ("show me the drift", "list_drift", {}),
    ("list critical drift", "list_drift", {"severity": "critical"}),
    ("any D3 drift?", "list_drift", {"rule": "D3"}),
    ("which assets are flagged", "list_flagged", {}),
    ("compare the last two scans", "compare_scans", {}),
    ("verify the manifest", "verify_manifest", {}),
    ("has the audit log been tampered with", "verify_manifest", {}),
    ("run a full scan", "run_scan", {}),
    ("scan the estate configs and containers", "run_scan", {"surfaces": ["config", "container"]}),
])
def test_the_verb_picks_the_tool_and_the_sentence_picks_the_asset(text, tool, arguments):
    decision = route(text, ASSETS)
    assert decision is not None and decision.kind == "tool", decision
    assert decision.tool == tool
    assert decision.arguments == arguments


@pytest.mark.parametrize("text, target", [
    ("migrate 200 assets", ""),
    ("migrate everything", ""),
    ("migrate all assets in payments-gateway", "payments-gateway"),
])
def test_estate_wide_migrations_become_one_call_the_blast_cap_can_see(text, target):
    decision = route(text, ASSETS)
    assert decision.tool == "migrate_asset"
    assert decision.arguments["target"] == target
    assert "asset_id" not in decision.arguments


@pytest.mark.parametrize("text", [
    "what are you?", "hello", "why is RSA weak", "explain harvest now decrypt later", "move on",
    "upgrade the report", "what should I migrate first",
])
def test_conceptual_and_conversational_text_goes_to_the_model(text):
    assert route(text, ASSETS) is None


# --------------------------------------------------------------------------
# Never guess
# --------------------------------------------------------------------------


def test_an_ambiguous_asset_is_asked_about_not_guessed():
    decision = route("migrate CardVault.java", ASSETS)
    assert decision.kind == "clarify"
    assert "asset_id" not in decision.arguments
    assert [c["id"] for c in decision.candidates] == ["cc33dd44-0003", "cc33dd44-0004"]  # best-ranked first
    assert "2 assets match" in decision.question
    assert "cc33dd44-0003" in decision.question and "cc33dd44-0004" in decision.question


def test_an_unknown_asset_after_an_explicit_verb_is_reported_not_forwarded():
    decision = route("migrate the mainframe", ASSETS)
    assert decision.kind == "clarify"
    assert decision.candidates == []
    assert "No asset matches" in decision.question


def test_a_pick_by_number_reruns_the_original_request_on_that_asset():
    question = route("migrate CardVault.java", ASSETS).question
    conversation = [{"role": "user", "content": "migrate CardVault.java"},
                    {"role": "assistant", "content": question}]
    by_number = route_conversation(conversation + [{"role": "user", "content": "2"}], ASSETS)
    assert (by_number.tool, by_number.arguments["asset_id"]) == ("migrate_asset", "cc33dd44-0004")
    assert by_number.rule.endswith(".picked")

    by_name = route_conversation(conversation + [{"role": "user", "content": "Signature.getInstance"}], ASSETS)
    assert by_name.arguments["asset_id"] == "cc33dd44-0004"


def test_a_reply_that_is_not_a_pick_is_routed_as_a_new_message():
    question = route("migrate CardVault.java", ASSETS).question
    conversation = [{"role": "user", "content": "migrate CardVault.java"},
                    {"role": "assistant", "content": question}]
    assert route_conversation(conversation + [{"role": "user", "content": "never mind, hello"}], ASSETS) is None
    fresh = route_conversation(conversation + [{"role": "user", "content": "show drift"}], ASSETS)
    assert fresh.tool == "list_drift"


def test_only_a_trailing_user_message_is_routed():
    assert route_conversation([{"role": "assistant", "content": "hi"}], ASSETS) is None
    assert route_conversation([], ASSETS) is None


# --------------------------------------------------------------------------
# Answers without a model
# --------------------------------------------------------------------------


def test_describe_copies_figures_and_reports_a_broken_audit_chain():
    decision = route("verify the manifest", ASSETS)
    text = agent_router.describe(decision, {
        "manifest": {"valid": True, "algorithm": "ML-DSA-65", "reason": "signature verified"},
        "audit_chain": {"valid": False, "entries": 7, "first_broken": 2, "reason": "entry hash mismatch"},
    })
    assert "ML-DSA-65" in text and "valid" in text
    assert "BROKEN at entry 2" in text


def test_describe_passes_refusals_through_verbatim():
    decision = route("migrate 200 assets", ASSETS)
    text = agent_router.describe(decision, {"error": "Refused: 138 assets exceeds the 25-asset cap.",
                                            "remedy": "Narrow the selection.", "refused_by": "control plane"})
    assert text == "Refused: 138 assets exceeds the 25-asset cap. Narrow the selection."
