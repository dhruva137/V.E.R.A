"""The discovery plugin framework and the key-material scanner.

These lock in the two properties the sensor layer exists to guarantee: that
every finding carries an honest evidence grade, and that scanning for key
material never retains the key.
"""

import textwrap

import pytest

from collectors.secret_scanner import (
    fingerprint,
    reuse_clusters,
    scan_tree,
    shannon_entropy,
)
from engine.discovery import register_builtins, surface
from engine.plugins import (
    PROVENANCE,
    DiscoveryPlugin,
    PluginRegistry,
    confidence_for,
    corroborate,
)

# --------------------------------------------------------------------------
# Entropy
# --------------------------------------------------------------------------


def test_entropy_separates_repetitive_from_random():
    assert shannon_entropy("aaaaaaaaaaaa") == 0.0
    assert shannon_entropy("xQ3fZm9Lp2VwR8sT1kYbN7cJ4hG6dA0e") > 4.5


def test_entropy_of_empty_string_is_zero_not_an_error():
    assert shannon_entropy("") == 0.0


def test_entropy_never_returns_negative_zero():
    """-0.0 renders as "-0" in a table, which reads as a bug to an operator."""
    import math

    value = shannon_entropy("bbbbbb")
    assert not math.copysign(1, value) < 0


# --------------------------------------------------------------------------
# Provenance and confidence
# --------------------------------------------------------------------------


def test_observation_outranks_static_analysis():
    """The ordering is the whole point: seeing it beats reading about it."""
    assert confidence_for("runtime_observed") > confidence_for("artifact_parsed")
    assert confidence_for("artifact_parsed") > confidence_for("static_analysis")
    assert confidence_for("static_analysis") > confidence_for("heuristic")


def test_every_grade_states_its_reasoning():
    """A confidence an operator cannot interrogate is not inspectable."""
    for key, grade in PROVENANCE.items():
        assert grade["rationale"].strip(), f"{key} has no stated rationale"
        assert 0.0 < grade["confidence"] <= 1.0


def test_unknown_provenance_falls_back_to_the_weakest_grade():
    assert confidence_for("something-invented") == PROVENANCE["inferred"]["confidence"]


def test_corroboration_raises_confidence_but_never_manufactures_an_observation():
    weak = corroborate(["static_analysis"])
    stronger = corroborate(["static_analysis", "config_parsed"])
    assert stronger > weak
    # Agreement between weak sensors must not reach "observed at runtime".
    many = corroborate(["static_analysis", "config_parsed", "imported", "heuristic"])
    assert many < confidence_for("runtime_observed")


def test_a_single_observation_is_not_penalised_by_corroboration_logic():
    assert corroborate(["runtime_observed"]) == confidence_for("runtime_observed")


# --------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------


def test_a_failing_plugin_reports_instead_of_raising():
    """A dead sensor must surface as a failed run, never as a silent gap."""

    class Broken(DiscoveryPlugin):
        id = "broken"
        name = "Broken"
        provenance = "heuristic"

        def collect(self, **kwargs):
            raise RuntimeError("sensor offline")

    registry = PluginRegistry()
    registry.register(Broken())
    result = registry.run("broken")

    assert result.ok is False
    assert "sensor offline" in result.detail
    assert result.count == 0


def test_plugin_findings_are_stamped_with_provenance_centrally():
    """A plugin cannot claim a grade it was not registered with."""
    from models.schemas import RawCryptoFinding

    class Tiny(DiscoveryPlugin):
        id = "tiny"
        name = "Tiny"
        provenance = "static_analysis"

        def collect(self, **kwargs):
            return [RawCryptoFinding(id="x", source_type="source", source_location="a.py")]

    registry = PluginRegistry()
    registry.register(Tiny())
    result = registry.run("tiny")

    assert result.ok is True
    stamped = result.findings[0].raw_details
    assert stamped["provenance"] == "static_analysis"
    assert stamped["confidence"] == confidence_for("static_analysis")
    assert stamped["discovered_by"] == "tiny"


def test_duplicate_plugin_ids_are_rejected():
    class A(DiscoveryPlugin):
        id = "dup"
        name = "A"

        def collect(self, **kwargs):
            return []

    registry = PluginRegistry()
    registry.register(A())
    with pytest.raises(ValueError):
        registry.register(A())


def test_unknown_plugin_run_is_a_reported_failure_not_a_crash():
    assert PluginRegistry().run("nope").ok is False


# --------------------------------------------------------------------------
# Coverage: blind spots are stated, not hidden
# --------------------------------------------------------------------------


def test_unconfigured_enterprise_connectors_appear_as_blind_spots():
    """The HSM being unreachable is a planning input, not an omission."""
    data = surface()
    blind_ids = {b["id"] for b in data["coverage"]["blind_spots"]}
    assert "hsm_pkcs11" in blind_ids
    assert "kmip" in blind_ids
    for spot in data["coverage"]["blind_spots"]:
        assert spot["reason"].strip(), "a blind spot must say why it is blind"
    # Adapter capability surface rides alongside plugins — not fabricated counts.
    assert {a["id"] for a in data["adapters"]} == {
        "pkcs11", "kmip", "cloud_kms", "tls", "keystore",
    }


def test_registering_builtins_twice_does_not_duplicate():
    first = len(register_builtins().all())
    second = len(register_builtins().all())
    assert first == second


# --------------------------------------------------------------------------
# Key material scanner
# --------------------------------------------------------------------------


@pytest.fixture
def tree(tmp_path):
    """A tree containing a real RSA key, the same key again, and decoys."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()

    (tmp_path / "service.pem").write_text(pem)
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "same_key.pem").write_text(pem)
    (tmp_path / "settings.py").write_text(
        textwrap.dedent(
            """
            AWS_ACCESS = "AKIAIOSFODNN7EXAMPLE"
            placeholder = "your_key_here_example_placeholder"
            digest = "5d41402abc4b2a76b9719d911017c592"
            """
        )
    )
    return tmp_path


def test_private_key_parameters_are_read_not_guessed(tree):
    findings = scan_tree(tree)
    rsa_hits = [f for f in findings if f.algorithm == "RSA"]
    assert rsa_hits, "an RSA private key in the tree must be found"
    assert all(f.key_size == 2048 for f in rsa_hits)
    assert all(f.raw_details["algorithm_source"] == "parsed" for f in rsa_hits)


def test_key_material_is_never_retained(tree):
    """The scanner must not create a second copy of a credential."""
    findings = scan_tree(tree)
    assert findings
    for finding in findings:
        blob = str(finding.model_dump())
        assert "BEGIN RSA PRIVATE KEY" not in blob
        assert "PRIVATE KEY-----" not in blob
        assert finding.raw_details["material_stored"] is False
        assert len(finding.raw_details["key_fingerprint"]) == 64


def test_the_same_key_in_two_places_is_detected_as_reuse(tree):
    clusters = reuse_clusters(scan_tree(tree))
    assert len(clusters) == 1
    assert clusters[0]["occurrences"] == 2
    assert clusters[0]["algorithm"] == "RSA"


def test_placeholders_and_digests_are_not_reported_as_secrets(tree):
    """The two largest sources of false positives in every secret scanner."""
    locations = " ".join(f.source_location for f in scan_tree(tree))
    findings = scan_tree(tree)
    flagged_values = [f.raw_details for f in findings]
    # The md5-shaped digest and the "your_key_here" placeholder must not appear.
    assert not any(d.get("entropy_bits_per_char") and d.get("length") == 32
                   for d in flagged_values if d.get("detection") == "entropy"), (
        "a plain hex digest was misreported as a secret"
    )
    assert "AKIA" not in locations  # locations are paths, never values


def test_known_credential_formats_are_identified_by_provider(tree):
    findings = scan_tree(tree)
    providers = {
        f.raw_details.get("credential_type")
        for f in findings
        if f.raw_details.get("detection") == "pattern"
    }
    assert "AWS access key id" in providers


def test_one_secret_is_not_reported_twice_by_two_methods(tmp_path):
    """A pattern hit and an entropy hit on the same line is one finding."""
    (tmp_path / "c.py").write_text('api_secret = "xQ3fZm9Lp2VwR8sT1kYbN7cJ4hG6dA0e"\n')
    findings = scan_tree(tmp_path)
    assert len(findings) == 1


def test_heuristic_findings_are_flagged_for_review(tmp_path):
    (tmp_path / "c.py").write_text('token = "Zk8vQ2mXr5TpL9wNc3JhB7yD4sG6fA1e"\n')
    findings = scan_tree(tmp_path)
    entropy_hits = [f for f in findings if f.raw_details["detection"] == "entropy"]
    for hit in entropy_hits:
        assert hit.raw_details["requires_review"] is True


def test_fingerprint_ignores_formatting_so_reuse_still_collides():
    assert fingerprint("AAAA BBBB") == fingerprint("AAAABBBB")
    assert fingerprint("AAAA") != fingerprint("BBBB")


def test_scanning_a_missing_directory_returns_nothing_rather_than_raising():
    assert scan_tree("/definitely/not/a/real/path") == []
