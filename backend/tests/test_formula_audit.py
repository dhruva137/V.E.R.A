"""Audit: are the formulas, constants and coefficients actually right?

Every number this product shows derives from a small set of formulas and a
smaller set of constants. This file checks them against their sources and
against their own stated properties, so a coefficient cannot drift without a
test failing.

Checked against: Mosca's inequality; Grigaliunas and Bruzgiene, MDPI
Electronics 2025 14(17) 3338 (QARS); the GRI Quantum Threat Timeline Report
2025 elicitation anchors.
"""

import pytest

from engine.qirs import (
    DEFAULT_W_H, DEFAULT_W_T, PROFILES, RISK_BANDS,
    compute_hndl, compute_qirs, compute_tnfl,
)
from engine.threat_model import (
    ANCHORS_T, ELICITATION_N, P_MEDIAN, P_OPTIMISTIC, P_PESSIMISTIC, ThreatModel,
)


@pytest.fixture(scope="module")
def model():
    return ThreatModel()


class Asset:
    """Minimal asset carrying the six policy inputs."""

    def __init__(self, **kw):
        self.quantum_vulnerable = kw.pop("vulnerable", True)
        defaults = dict(x_c=5.0, x_i=5.0, y=1.0, s=0.8, e=0.8, c=0.8)
        for name, value in defaults.items():
            setattr(self, name, kw.pop(name, value))
        self.h_score = 0.0
        self.t_score = 0.0


def test_no_crqc_exists_today():
    """S_Z(0) = 1. Anything else means the curve is fitted wrong at the origin."""
    assert P_MEDIAN[0] == 0.0
    assert P_OPTIMISTIC[0] == 0.0
    assert P_PESSIMISTIC[0] == 0.0


def test_survival_starts_at_one(model):
    for value in model.survival(0.0):
        assert value == pytest.approx(1.0, abs=1e-6)


def test_the_readings_are_ordered_at_every_anchor():
    """Optimistic must mean 'arrives later' everywhere, or the band is not a
    band but three curves crossing."""
    for t, opt, med, pes in zip(ANCHORS_T, P_OPTIMISTIC, P_MEDIAN, P_PESSIMISTIC):
        assert opt <= med <= pes, f"readings cross at t={t}"


def test_survival_is_monotone_non_increasing(model):
    """Waiting longer cannot make arrival less likely."""
    previous = (1.0, 1.0, 1.0)
    for step in range(0, 61):
        current = model.survival(0.5 * step)
        for now, before in zip(current, previous):
            assert now <= before + 1e-9, f"survival rose at t={0.5 * step}"
        previous = current


def test_survival_stays_within_zero_and_one(model):
    for t in (0.0, 1.0, 5.0, 10.0, 25.0, 50.0, 100.0):
        for value in model.survival(t):
            assert -1e-9 <= value <= 1.0 + 1e-9


def test_the_headline_2030_figure_is_reproduced(model):
    """The GRI report's ~34% by 2030 is the most-quoted number here. If the fit
    does not reproduce it, every downstream figure is quietly wrong."""
    _, median, _ = model.survival(5.0)
    assert 1.0 - median == pytest.approx(0.34, abs=0.02)


def test_the_ten_year_band_matches_the_published_range(model):
    """The report gives 28 to 49 percent at ten years depending on pooling."""
    optimistic, _, pessimistic = model.survival(10.0)
    assert 1.0 - optimistic == pytest.approx(0.28, abs=0.03)
    assert 1.0 - pessimistic == pytest.approx(0.49, abs=0.03)


def test_the_elicitation_size_is_recorded():
    """A subjective prior with no stated sample size cannot be argued with."""
    assert ELICITATION_N == 26


def test_hndl_is_the_qars_shape(model):
    """H = S * E * [1 - S_Z(X_c + Y)], computed by hand."""
    asset = Asset(s=0.7, e=0.9, x_c=6.0, y=2.0)
    _, median, _ = model.survival(8.0)
    assert compute_hndl(asset, model) == pytest.approx(0.7 * 0.9 * (1 - median), abs=1e-6)


def test_tnfl_uses_the_minimum_not_the_sum(model):
    """The entire contribution of this project. If this ever becomes a sum, the
    integrity axis collapses into a second confidentiality axis."""
    asset = Asset(c=0.9, x_i=12.0, y=3.0)
    _, at_min, _ = model.survival(3.0)
    assert compute_tnfl(asset, model) == pytest.approx(0.9 * (1 - at_min), abs=1e-6)


def test_hndl_grows_without_bound_as_migration_slips(model):
    """Additive in Y: every month of delay adds directly to the horizon."""
    values = [compute_hndl(Asset(x_c=5.0, y=y), model) for y in (0.5, 2.0, 5.0, 10.0)]
    assert values == sorted(values)
    assert values[-1] > values[0]


def test_tnfl_saturates_once_migration_exceeds_the_trust_horizon(model):
    """Capped by min(): past X_i further slip changes nothing, because the
    anchor retires before a forgery could matter."""
    below = compute_tnfl(Asset(x_i=2.0, y=1.0), model)
    at = compute_tnfl(Asset(x_i=2.0, y=2.0), model)
    beyond = compute_tnfl(Asset(x_i=2.0, y=20.0), model)
    assert at > below
    assert beyond == pytest.approx(at, abs=1e-9), "TNFL must saturate at X_i"


def test_the_two_axes_are_genuinely_different(model):
    """A TLS key exchange and a root CA must not rank alike. This is the claim
    the whole product rests on."""
    kex = PROFILES["tls_key_exchange"]
    root = PROFILES["root_ca"]
    kex_asset = Asset(x_c=kex.x_c, x_i=kex.x_i, y=kex.y, s=kex.s, e=kex.e, c=kex.c)
    root_asset = Asset(x_c=root.x_c, x_i=root.x_i, y=root.y, s=root.s, e=root.e, c=root.c)

    assert compute_hndl(kex_asset, model) > compute_hndl(root_asset, model)
    assert compute_tnfl(root_asset, model) > compute_tnfl(kex_asset, model)


def test_a_quantum_safe_asset_scores_zero_on_both_axes(model):
    safe = Asset(vulnerable=False)
    assert compute_hndl(safe, model) == 0.0
    assert compute_tnfl(safe, model) == 0.0


def test_both_axes_are_bounded_by_one(model):
    worst = Asset(s=1.0, e=1.0, c=1.0, x_c=100.0, x_i=100.0, y=100.0)
    assert compute_hndl(worst, model) <= 1.0
    assert compute_tnfl(worst, model) <= 1.0


def test_the_composite_weights_sum_to_one():
    """Otherwise QIRS is not on the same scale as its own axes."""
    assert DEFAULT_W_H + DEFAULT_W_T == pytest.approx(1.0, abs=1e-9)


def test_the_composite_is_the_stated_weighted_sum():
    assert compute_qirs(0.4, 0.6) == pytest.approx(0.5 * 0.4 + 0.5 * 0.6, abs=1e-9)


def test_the_composite_lies_between_its_axes():
    for h, t in ((0.1, 0.9), (0.9, 0.1), (0.3, 0.3)):
        assert min(h, t) - 1e-9 <= compute_qirs(h, t) <= max(h, t) + 1e-9


def test_risk_bands_are_ordered_and_descending():
    thresholds = [threshold for threshold, _ in RISK_BANDS]
    assert thresholds == sorted(thresholds, reverse=True)
    assert all(0.0 < t < 1.0 for t in thresholds)


def test_every_policy_input_is_in_range():
    for name, profile in PROFILES.items():
        assert profile.x_c > 0, f"{name}: X_c must be positive"
        assert profile.x_i > 0, f"{name}: X_i must be positive"
        assert profile.y > 0, f"{name}: Y must be positive"
        for weight in ("s", "e", "c"):
            value = getattr(profile, weight)
            assert 0.0 <= value <= 1.0, f"{name}: {weight}={value} outside [0,1]"


def test_every_profile_states_its_reasoning():
    """A policy assumption with no written rationale is indistinguishable from
    a number somebody typed."""
    for name, profile in PROFILES.items():
        assert len(profile.rationale) > 40, f"{name} has no usable rationale"
        assert profile.label


def test_the_root_ca_row_is_the_argument():
    """Low exposure, maximum blast radius. This single row is why a second axis
    is needed, so it is asserted rather than left to drift."""
    root = PROFILES["root_ca"]
    assert root.e <= 0.3, "a root CA signs no interceptable traffic"
    assert root.c == 1.0, "a root CA is the maximum blast radius"
    assert root.x_i >= 10.0, "a root CA is trusted for many years"


def test_the_tls_key_exchange_row_is_its_mirror():
    kex = PROFILES["tls_key_exchange"]
    assert kex.e == 1.0, "session traffic is fully interceptable"
    assert kex.x_i < 0.1, "a session key's trust horizon is one connection"
    assert kex.x_c >= 5.0, "the traffic it protects must stay secret for years"


def test_hardware_bound_classes_carry_the_longest_migration():
    assert PROFILES["firmware_signing"].y > PROFILES["tls_cipher_suite"].y
    assert PROFILES["root_ca"].y > PROFILES["tls_certificate"].y


def test_backup_retention_is_the_longest_confidentiality_horizon():
    """Archives are the worst harvest-now exposure in any estate."""
    longest = max(PROFILES.values(), key=lambda p: p.x_c)
    assert longest.label.startswith("Backup")


# --------------------------------------------------------------------------
# Grover-bounded residual security
# --------------------------------------------------------------------------


def test_grover_halves_symmetric_strength():
    from engine.taxonomy import grover_residual
    result = grover_residual(256, "block-cipher")
    assert result["applies"] is True
    assert result["residual_bits"] == 128


def test_aes128_and_aes256_are_not_treated_alike():
    """The whole reason a boolean was insufficient: these are 2^64 apart."""
    from engine.taxonomy import classify_finding

    def band(alg):
        return classify_finding(
            algorithm=alg, key_size=None, cipher_suite=None,
            key_exchange=None, protocol=None,
        )["grover"]["band"]

    assert band("AES-256") == "comfortable"
    assert band("AES-128") == "weakened"


def test_hash_collision_strength_is_not_halved_twice():
    """`classical_bits` for a hash is already the birthday bound. Halving it
    again would report SHA-256 as 64-bit, wrong by a factor of 2^64."""
    from engine.taxonomy import classify_finding

    sha256 = classify_finding(
        algorithm="SHA-256", key_size=None, cipher_suite=None,
        key_exchange=None, protocol=None,
    )
    assert sha256["classical_bits"] == 128
    assert sha256["grover"]["residual_bits"] == 128
    assert sha256["grover"]["applies"] is False
    assert "birthday bound" in sha256["grover"]["note"]


def test_asymmetric_primitives_are_excluded_from_the_grover_discount():
    """Shor breaks them outright; a residual-bits figure would understate it."""
    from engine.taxonomy import grover_residual
    result = grover_residual(2048, "pke")
    assert result["applies"] is False
    assert result["residual_bits"] is None
    assert "Shor" in result["note"]


def test_grover_bands_are_ordered_and_each_states_guidance():
    from engine.taxonomy import GROVER_BANDS
    thresholds = [t for t, _, _ in GROVER_BANDS]
    assert thresholds == sorted(thresholds, reverse=True)
    for _, name, guidance in GROVER_BANDS:
        assert name and len(guidance) > 20


def test_an_unknown_key_size_yields_no_residual_rather_than_a_guess():
    from engine.taxonomy import grover_residual
    assert grover_residual(None, "block-cipher")["residual_bits"] is None
