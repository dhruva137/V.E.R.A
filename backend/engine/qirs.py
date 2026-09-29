"""M4 - QIRS scoring engine.

Implements the two-axis model from blueprint section 4, extending the
Quantum-Adjusted Risk Score within the PAREK framework (*Towards a Unified
Quantum Risk Assessment*, MDPI Electronics 2025, 14(17), 3338).

    Axis 1, confidentiality (harvest now, decrypt later):

        H = S . E . [1 - S_Z(X_c + Y)]

    Traffic sent at any point during the migration window [0, Y] is harvestable
    under vulnerable crypto. The last such traffic must stay secret for a
    further X_c years. Harm occurs if a CRQC arrives inside that whole window,
    so the horizon is the *sum*.

    Axis 2, integrity (trust now, forge later):

        T = C . [1 - S_Z(min(X_i, Y))]

    A trust anchor is forgeable only while it is both still in service and not
    yet migrated. Migrating early closes the window; retiring the anchor early
    also closes it. Whichever happens first governs, so the horizon is the
    *minimum*.

THE RESULT THAT MATTERS
-----------------------
Confidentiality risk is additive in migration time; integrity risk is capped by
it. X_c + Y grows without bound as migration slips, while min(X_i, Y) saturates
at X_i. A single-axis score cannot express that difference, which is why
long-lived signing assets are systematically mis-ranked by tools that score
confidentiality only. `explain_asset` walks the whole derivation so this is
auditable per asset rather than asserted.

Composite:

    QIRS = w_H . H + w_T . T

reported with a band across the survival ensemble. Priority is negative slack
first, then QIRS descending.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from engine import classification
from engine.agility import agility_for
from engine.expiry import band_for, days_remaining
from engine.kb.libraries import classify as classify_library
from engine.taxonomy import classify_finding
from engine.threat_model import ThreatModel
from models.schemas import CryptoAsset

# Sector-calibrated composite weights. Equal weighting is the neutral default;
# the API accepts an override so the sensitivity view can show how the
# composite ranking (not the per-axis ranking) moves with them.
DEFAULT_W_H = 0.5
DEFAULT_W_T = 0.5


@dataclass(frozen=True)
class PolicyProfile:
    """Per-asset-class defaults for the six QIRS inputs.

    These are policy inputs, not measurements. Every one is a stated assumption
    an operator is expected to override with their own data classification and
    effort estimates; they are surfaced in the asset detail view for exactly
    that reason.

    x_c  confidentiality horizon - years the protected data must stay secret
    x_i  trust horizon - years the trust anchor remains relied upon
    y    migration effort, in years
    s    data sensitivity weight, 0-1
    e    exposure: internet-facing, interceptable, traffic volume, 0-1
    c    blast radius: how many downstream systems trust this anchor, 0-1
    """

    label: str
    x_c: float
    x_i: float
    y: float
    s: float
    e: float
    c: float
    rationale: str


# Keyed by asset_class. Collectors/adapters must set asset_class; that is what
# makes an HSM-rooted CA behave differently from a marketing TLS cert.
PROFILES: dict[str, PolicyProfile] = {
    "tls_certificate": PolicyProfile(
        "TLS server certificate", x_c=7.0, x_i=1.5, y=0.25, s=0.7, e=1.0, c=0.35,
        rationale=(
            "Public TLS certificates are short-lived by policy (398 days maximum) and "
            "automatable to re-issue, so both the trust horizon and the migration "
            "effort are small. The blast radius is limited to the one service."
        ),
    ),
    "tls_key_exchange": PolicyProfile(
        "TLS key exchange group", x_c=10.0, x_i=0.02, y=0.25, s=0.85, e=1.0, c=0.15,
        rationale=(
            "The primary harvest-now-decrypt-later surface. Session keys are ephemeral "
            "(trust horizon is one connection), but the traffic they protect carries a "
            "long confidentiality requirement, so this scores high on HNDL and near "
            "zero on TNFL. This is the asymmetry a single-axis model cannot express."
        ),
    ),
    "tls_cipher_suite": PolicyProfile(
        "TLS cipher suite", x_c=7.0, x_i=0.02, y=0.15, s=0.6, e=1.0, c=0.1,
        rationale=(
            "Record-layer configuration. A one-line change on the server, so migration "
            "effort is minimal."
        ),
    ),
    "root_ca": PolicyProfile(
        "Root certificate authority", x_c=2.0, x_i=20.0, y=3.5, s=0.9, e=0.2, c=1.0,
        rationale=(
            "A root CA signs nothing directly but is trusted by everything. Re-rooting "
            "a PKI means redistributing the trust anchor to every relying party, which "
            "is a multi-year programme. Maximum blast radius, minimal direct exposure - "
            "the exact profile a confidentiality-only score gets wrong."
        ),
    ),
    "issuing_ca": PolicyProfile(
        "Issuing certificate authority", x_c=2.0, x_i=8.0, y=2.0, s=0.85, e=0.3, c=0.85,
        rationale=(
            "Subordinate CAs can be re-issued under a new root faster than the root "
            "itself, but every certificate beneath them must be re-enrolled."
        ),
    ),
    "code_signing": PolicyProfile(
        "Code signing key", x_c=5.0, x_i=10.0, y=2.0, s=0.9, e=0.5, c=0.9,
        rationale=(
            "Signed artefacts are verified for as long as they are deployed, so the "
            "trust horizon runs well past the certificate's own validity. Rotating the "
            "key means re-signing and redistributing every artefact still in the field."
        ),
    ),
    "firmware_signing": PolicyProfile(
        "Firmware signing key", x_c=5.0, x_i=12.0, y=3.0, s=0.95, e=0.4, c=0.95,
        rationale=(
            "Embedded devices verify firmware against a key burned in at manufacture. "
            "The trust horizon is the fleet's service life, and migration requires a "
            "hardware refresh cycle for devices that cannot accept a new anchor - the "
            "single longest migration in a typical estate."
        ),
    ),
    "payment_hsm": PolicyProfile(
        "Payment HSM key", x_c=8.0, x_i=6.0, y=2.5, s=0.95, e=0.35, c=0.9,
        rationale=(
            "HSM-resident keys cannot migrate ahead of firmware support from the HSM "
            "vendor, which is the binding constraint rather than internal effort. "
            "Cardholder data carries a long confidentiality requirement."
        ),
    ),
    "device_identity": PolicyProfile(
        "Device identity certificate", x_c=3.0, x_i=8.0, y=2.5, s=0.7, e=0.6, c=0.75,
        rationale=(
            "Per-device identities issued at provisioning and relied on for the device "
            "lifetime. Migration is gated by the fleet replacement rate."
        ),
    ),
    "token_signing": PolicyProfile(
        "Token / assertion signing key", x_c=1.0, x_i=3.0, y=0.75, s=0.8, e=0.8, c=0.8,
        rationale=(
            "JWT and SAML signing keys are rotatable in software, but every relying "
            "party must accept the new key, so the blast radius is high even though "
            "the effort is moderate. Tokens themselves are short-lived, so the "
            "confidentiality horizon is small."
        ),
    ),
    "vpn_ipsec": PolicyProfile(
        "VPN / IPsec tunnel", x_c=9.0, x_i=2.0, y=1.0, s=0.85, e=1.0, c=0.5,
        rationale=(
            "Site-to-site tunnels carry bulk internal traffic and are trivially "
            "interceptable at the network edge. High-value harvesting target."
        ),
    ),
    "database_tls": PolicyProfile(
        "Database transport encryption", x_c=10.0, x_i=2.0, y=0.75, s=0.95, e=0.4, c=0.5,
        rationale=(
            "Carries the highest-sensitivity data in the estate, but on internal "
            "networks, so exposure is lower than an edge service while the "
            "confidentiality horizon is the longest."
        ),
    ),
    "ssh_key": PolicyProfile(
        "SSH host / user key", x_c=4.0, x_i=4.0, y=0.5, s=0.75, e=0.7, c=0.45,
        rationale="Rotatable via configuration management, but widely distributed.",
    ),
    "ssh_key_exchange": PolicyProfile(
        "SSH key exchange", x_c=8.0, x_i=0.02, y=0.3, s=0.75, e=0.9, c=0.2,
        rationale=(
            "Administrative sessions carry credentials, configuration and data dumps, "
            "and are recordable at the network edge like any other session. A server "
            "change once the SSH build supports a hybrid, so migration effort is small."
        ),
    ),
    "config": PolicyProfile(
        "Server crypto configuration", x_c=6.0, x_i=1.5, y=0.3, s=0.6, e=0.8, c=0.35,
        rationale=(
            "Protocol and cipher directives in server configuration. Cheap to change "
            "once the supporting library ships the new algorithms."
        ),
    ),
    "source": PolicyProfile(
        "Cryptographic API call in source", x_c=5.0, x_i=5.0, y=1.5, s=0.65, e=0.4, c=0.55,
        rationale=(
            "Hard-coded algorithm choices require a develop, test and release cycle, "
            "and often a library upgrade underneath. Slower than configuration, faster "
            "than hardware."
        ),
    ),
    "backup_encryption": PolicyProfile(
        "Backup / archive encryption", x_c=15.0, x_i=1.0, y=1.0, s=0.9, e=0.2, c=0.3,
        rationale=(
            "Retention policy sets the confidentiality horizon directly, and it is the "
            "longest in the estate. Archives written today under vulnerable key "
            "transport stay readable to whoever holds them."
        ),
    ),
    "crypto_library": PolicyProfile(
        "Cryptographic library", x_c=6.0, x_i=3.0, y=1.0, s=0.6, e=0.5, c=0.7,
        rationale=(
            "A library version is a migration gate for everything linked against it: "
            "no application can negotiate ML-KEM through a library that predates it. "
            "Upgrading is a dependency bump plus regression testing, and every "
            "dependent application inherits the result."
        ),
    ),
    "binary": PolicyProfile(
        "Cryptography compiled into a binary", x_c=5.0, x_i=5.0, y=2.0, s=0.65, e=0.5, c=0.55,
        rationale=(
            "An algorithm compiled into a shipped artefact changes only with a rebuild "
            "and redeploy, and for third-party binaries only when the vendor ships one."
        ),
    ),
    "embedded_certificate": PolicyProfile(
        "Certificate embedded in a binary", x_c=2.0, x_i=8.0, y=1.0, s=0.7, e=0.5, c=0.6,
        rationale=(
            "A pinned or bundled certificate is trusted until the artefact carrying it "
            "is rebuilt and redeployed, so its trust horizon outlives its own rotation."
        ),
    ),
    "trust_store": PolicyProfile(
        "Certificate trust store", x_c=1.0, x_i=15.0, y=2.0, s=0.7, e=0.4, c=0.85,
        rationale=(
            "A trust store decides whose signatures an image or host accepts. Its roots "
            "are relied on for their full lifetime, and no PQC roots are broadly "
            "distributed yet, so replacing them is a coordinated, multi-year change."
        ),
    ),
    "embedded_private_key": PolicyProfile(
        "Private key embedded in an artefact", x_c=5.0, x_i=5.0, y=0.5, s=0.9, e=0.7, c=0.6,
        rationale=(
            "Anyone holding the artefact holds the key. Rotating it is quick; finding "
            "every copy that shipped is not. Treated as exposed regardless of quantum."
        ),
    ),
    "generic_key": PolicyProfile(
        "Cryptographic key (unclassified)", x_c=7.0, x_i=5.0, y=1.5, s=0.7, e=0.4, c=0.6,
        rationale=(
            "No asset class recorded. Mid-range defaults applied and flagged for "
            "operator review - an unclassified key is a gap in the inventory, not a "
            "safe asset."
        ),
    ),
}


def resolve_profile(asset: CryptoAsset) -> PolicyProfile:
    """Pick the policy profile for an asset.

    Order: explicit asset_class, then TLS shape signals (usage / fields), then
    pack-data hints for legacy assets, then generic_key. Never branches on
    source_type — that legacy map lives in engine.packs as DATA.
    """
    if asset.asset_class and asset.asset_class in PROFILES:
        return PROFILES[asset.asset_class]

    # Shape signals — independent of how the finding was collected.
    if asset.usage == "key_exchange" or asset.key_exchange:
        return PROFILES["tls_key_exchange"]
    if asset.cipher_suite:
        return PROFILES["tls_cipher_suite"]
    if asset.cert_subject or asset.cert_serial:
        return PROFILES["tls_certificate"]

    try:
        from engine.packs import resolve_qirs_profile_key
    except ImportError:  # pragma: no cover - packs always ships with the engine
        resolve_qirs_profile_key = None  # type: ignore[assignment]

    if resolve_qirs_profile_key is not None:
        key = resolve_qirs_profile_key(asset)
        if key and key in PROFILES:
            return PROFILES[key]

    return PROFILES["generic_key"]


def apply_profile(asset: CryptoAsset) -> CryptoAsset:
    """Populate the six QIRS inputs from the resolved profile.

    Explicit per-asset overrides always win, so an operator supplying a real
    data-retention figure is never silently replaced by a default.
    """
    profile = resolve_profile(asset)
    asset.profile_label = profile.label
    asset.profile_rationale = profile.rationale

    for field in ("x_c", "x_i", "y", "s", "e", "c"):
        if getattr(asset, field, None) in (None, 0.0):
            setattr(asset, field, getattr(profile, field))

    return asset


def classify_asset(asset: CryptoAsset) -> CryptoAsset:
    """Run the taxonomy over an asset and record the outcome.

    A `crypto_library` asset is judged on a different question - does this
    library version block PQC migration? - answered by the library KB.
    """
    if asset.asset_class == "crypto_library":
        result = classify_library(asset.raw_details or {})
    else:
        result = classify_finding(
            algorithm=asset.algorithm,
            key_size=asset.key_size,
            cipher_suite=asset.cipher_suite,
            key_exchange=asset.key_exchange,
            protocol=asset.protocol,
        )
    asset.verdict = result["verdict"]
    asset.quantum_vulnerable = result["quantum_vulnerable"]
    asset.classically_broken = result["classically_broken"]
    asset.grover_weakened = result["grover_weakened"]
    asset.vulnerability_reason = result["rationale"]
    asset.primitive = result["primitive"]
    asset.classical_bits = result["classical_bits"]
    asset.nist_quantum_level = result["nist_quantum_level"]
    asset.pqc_replacement = result["pqc_replacement"]
    asset.curve = result["curve"]
    asset.oid = result["oid"]
    asset.suite_breakdown = result["suite"]
    asset.classification_components = result["components"]
    return asset


def compute_hndl(asset: CryptoAsset, threat_model: ThreatModel) -> float:
    """H = S . E . [1 - S_Z(X_c + Y)] under the median survival curve.

    Quantum-safe assets score zero: there is no harvest-now-decrypt-later
    exposure when the key exchange is not Shor-breakable in the first place.
    """
    if not asset.quantum_vulnerable:
        return 0.0
    horizon = asset.x_c + asset.y
    _, median, _ = threat_model.survival(horizon)
    return round(asset.s * asset.e * (1.0 - median), 6)


def compute_tnfl(asset: CryptoAsset, threat_model: ThreatModel) -> float:
    """T = C . [1 - S_Z(min(X_i, Y))] under the median survival curve."""
    if not asset.quantum_vulnerable:
        return 0.0
    horizon = min(asset.x_i, asset.y)
    _, median, _ = threat_model.survival(horizon)
    return round(asset.c * (1.0 - median), 6)


def compute_qirs(h: float, t: float, w_h: float = DEFAULT_W_H, w_t: float = DEFAULT_W_T) -> float:
    return round(w_h * h + w_t * t, 6)


def compute_qirs_band(
    asset: CryptoAsset,
    threat_model: ThreatModel,
    w_h: float = DEFAULT_W_H,
    w_t: float = DEFAULT_W_T,
) -> tuple[float, float]:
    """QIRS under the optimistic and pessimistic ensemble members.

    This is the band the blueprint insists on reporting instead of a single
    number. Note it is a band over *interpretations of one elicitation*, not a
    statistical confidence interval, and the UI says so.
    """
    if not asset.quantum_vulnerable:
        return 0.0, 0.0

    h_horizon = asset.x_c + asset.y
    t_horizon = min(asset.x_i, asset.y)

    s_opt_h, _, s_pes_h = threat_model.survival(h_horizon)
    s_opt_t, _, s_pes_t = threat_model.survival(t_horizon)

    # Higher survival means lower risk, so the optimistic survival curve gives
    # the low end of the risk band.
    low = w_h * (asset.s * asset.e * (1.0 - s_opt_h)) + w_t * (asset.c * (1.0 - s_opt_t))
    high = w_h * (asset.s * asset.e * (1.0 - s_pes_h)) + w_t * (asset.c * (1.0 - s_pes_t))
    return round(min(low, high), 6), round(max(low, high), 6)


def score_assets(
    assets: list[CryptoAsset],
    threat_model: ThreatModel,
    w_h: float = DEFAULT_W_H,
    w_t: float = DEFAULT_W_T,
) -> list[CryptoAsset]:
    """Classify, apply policy defaults, and score every asset.

    Expiry and agility are attached in the same pass. They are not part of the
    risk score - they answer "what is already overdue" and "what can actually
    be changed today" - but computing them here means every consumer reads a
    precomputed value instead of recomputing per request.
    """
    # Read the clock once. Scoring a large estate row by row against
    # datetime.now() would let assets near a band boundary land on different
    # sides of it within a single scan.
    now = datetime.now(timezone.utc)

    for asset in assets:
        classify_asset(asset)
        apply_profile(asset)
        classification.apply(asset)
        asset.h_score = compute_hndl(asset, threat_model)
        asset.t_score = compute_tnfl(asset, threat_model)
        asset.qirs = compute_qirs(asset.h_score, asset.t_score, w_h, w_t)
        asset.qirs_low, asset.qirs_high = compute_qirs_band(asset, threat_model, w_h, w_t)

        asset.expiry_days = days_remaining(asset, now)
        asset.expiry_band = band_for(asset.expiry_days)
        band = agility_for(asset)
        asset.agility_key = band["key"]
        asset.agility_label = band["label"]
        asset.agility_actionable = band["actionable_now"]
    return assets


# Risk bands are set on the *dominant axis*, max(H, T), not on the composite.
#
# QIRS averages two structurally different risks, so an asset that is extreme on
# one axis and null on the other gets halved. That is exactly the root-CA case
# the model exists to surface: near-zero confidentiality risk, maximum integrity
# risk. Banding on the composite would bury it in the middle of the estate.
# The composite still drives ordering within a band.
#
# The absolute values are low by construction - H and T are bounded above by
# 1 - S_Z(horizon), which at a 10-year horizon is about 0.49 under the
# pessimistic curve. A score of 0.30 means a high-sensitivity asset with roughly
# even odds of a CRQC inside its exposure window. Inflating these to fill a
# 0-100 scale would be dishonest, so the UI shows the raw value and a percentile
# within the scanned estate instead.
RISK_BANDS = [
    (0.30, "high"),
    (0.18, "medium"),
    (0.08, "low"),
]


def dominant_axis(asset: CryptoAsset) -> tuple[str, float]:
    """Which axis governs this asset, and its value."""
    if asset.t_score > asset.h_score:
        return "TNFL", asset.t_score
    return "HNDL", asset.h_score


def assign_risk_level(asset: CryptoAsset) -> str:
    """Bucket an asset for display.

    Negative slack dominates: an asset that cannot meet its statutory milestone
    even starting today is a scheduling fact, not a scoring opinion, and it
    outranks a higher score with time still on the clock.
    """
    if not asset.quantum_vulnerable:
        # Classically broken crypto still needs fixing - it is just not a
        # post-quantum migration item, so it gets its own band rather than
        # being ranked against assets on the PQC track.
        return "informational" if asset.classically_broken else "safe"

    _, dominant = dominant_axis(asset)

    if asset.slack_months < 0:
        return "critical" if dominant >= 0.20 else "high"

    for threshold, level in RISK_BANDS:
        if dominant >= threshold:
            return level
    return "minimal"


def order_assets(
    assets: list[CryptoAsset],
    threat_model: ThreatModel | None = None,
) -> list[CryptoAsset]:
    """Order the migration backlog by Mosca category, then margin, then QIRS.

    The problem this answers is the one Mosca's inequality was written for: which
    assets will still be exposed when a CRQC arrives, given how long they must
    stay safe and how long they take to move. So quantum-vulnerable assets are
    grouped by their Mosca category (engine.mosca) - exposed under every reading,
    under the median, only if CRQC comes early, or clear. Inside a group the
    widest median margin (X + Y - Z, the years of exposure) comes first, and
    QIRS breaks ties, so the two-axis score decides between assets that share
    the same exposure.

    Everything that is not a post-quantum item follows: classically broken
    crypto, then algorithms nobody could resolve, then assets already safe. A
    3DES key is urgent, but it is classical hygiene, and mixing it into the PQC
    backlog produces a list nobody can action.

    Statutory slack is deliberately *not* a sort key. It is shown next to every
    asset, but the order is a statement about the quantum threat.
    """
    from engine import mosca

    arrivals = mosca.arrival_years(threat_model)
    for asset in assets:
        reading = mosca.assess(asset, arrivals=arrivals)
        asset.mosca_category = reading["category"]
        asset.mosca_axis = reading.get("axis", "")
        margins = reading.get("margin_years")
        asset.mosca_margin_years = margins["median"] if margins else None

    def sort_key(asset: CryptoAsset):
        if asset.quantum_vulnerable:
            margin = asset.mosca_margin_years if asset.mosca_margin_years is not None else float("-inf")
            return (0, mosca.category_rank(asset.mosca_category), -margin, -asset.qirs, asset.name)
        # Non-PQC work, ordered classical breakage -> unknown -> safe.
        tier = 1 if asset.classically_broken else (2 if asset.verdict == "unknown" else 3)
        return (tier, 0, 0.0, 0.0, asset.name)

    ordered = sorted(assets, key=sort_key)
    for index, asset in enumerate(ordered, start=1):
        asset.priority_rank = index
    return ordered


def explain_asset(asset: CryptoAsset, threat_model: ThreatModel) -> dict:
    """Full auditable derivation for one asset.

    This backs the 2:30 demo beat - drill into one asset and show every step
    from inputs to priority, with no hidden constants.
    """
    h_horizon = asset.x_c + asset.y
    t_horizon = min(asset.x_i, asset.y)

    s_opt_h, s_med_h, s_pes_h = threat_model.survival(h_horizon)
    s_opt_t, s_med_t, s_pes_t = threat_model.survival(t_horizon)

    return {
        "asset_id": asset.id,
        "name": asset.name,
        "profile": {
            "label": asset.profile_label,
            "rationale": asset.profile_rationale,
        },
        "classification": {
            "verdict": asset.verdict,
            "quantum_vulnerable": asset.quantum_vulnerable,
            "classically_broken": asset.classically_broken,
            "reason": asset.vulnerability_reason,
            "components": asset.classification_components,
            "suite": asset.suite_breakdown,
            "pqc_replacement": asset.pqc_replacement,
        },
        "inputs": [
            {"symbol": "X_c", "value": asset.x_c, "unit": "years",
             "meaning": "Confidentiality horizon: how long the protected data must stay secret"},
            {"symbol": "X_i", "value": asset.x_i, "unit": "years",
             "meaning": "Trust horizon: how long this anchor remains relied upon"},
            {"symbol": "Y", "value": asset.y, "unit": "years",
             "meaning": "Migration effort for this asset class"},
            {"symbol": "S", "value": asset.s, "unit": "weight",
             "meaning": "Data sensitivity"},
            {"symbol": "E", "value": asset.e, "unit": "weight",
             "meaning": "Exposure: internet-facing and interceptable"},
            {"symbol": "C", "value": asset.c, "unit": "weight",
             "meaning": "Blast radius: downstream systems trusting this anchor"},
        ],
        "hndl": {
            "formula": "H = S . E . [1 - S_Z(X_c + Y)]",
            "horizon_expression": f"X_c + Y = {asset.x_c} + {asset.y} = {round(h_horizon, 4)} years",
            "horizon": round(h_horizon, 4),
            "s_z_median": round(s_med_h, 6),
            "s_z_band": [round(s_pes_h, 6), round(s_opt_h, 6)],
            "substitution": (
                f"H = {asset.s} x {asset.e} x [1 - {round(s_med_h, 4)}] = {asset.h_score}"
            ),
            "value": asset.h_score,
            "note": (
                "Additive in migration time. Every month migration slips extends the "
                "window during which harvestable traffic is still being generated."
            ),
        },
        "tnfl": {
            "formula": "T = C . [1 - S_Z(min(X_i, Y))]",
            "horizon_expression": (
                f"min(X_i, Y) = min({asset.x_i}, {asset.y}) = {round(t_horizon, 4)} years"
            ),
            "horizon": round(t_horizon, 4),
            "binding_term": "Y (migration finishes first)" if asset.y <= asset.x_i
                            else "X_i (the anchor retires first)",
            "s_z_median": round(s_med_t, 6),
            "s_z_band": [round(s_pes_t, 6), round(s_opt_t, 6)],
            "substitution": f"T = {asset.c} x [1 - {round(s_med_t, 4)}] = {asset.t_score}",
            "value": asset.t_score,
            "note": (
                "Capped by migration time. Once Y exceeds X_i the exposure window stops "
                "growing, because the anchor retires before the forgery matters."
            ),
        },
        "composite": {
            "formula": f"QIRS = {DEFAULT_W_H} . H + {DEFAULT_W_T} . T",
            "substitution": (
                f"QIRS = {DEFAULT_W_H} x {asset.h_score} + {DEFAULT_W_T} x {asset.t_score} "
                f"= {asset.qirs}"
            ),
            "value": asset.qirs,
            "band": [asset.qirs_low, asset.qirs_high],
            "band_note": (
                "Range across the optimistic and pessimistic readings of the GRI 2025 "
                "elicitation. Not a statistical confidence interval."
            ),
        },
        "regulatory": {
            "persona": asset.persona,
            "persona_source": asset.persona_source,
            "binding_phase": asset.binding_phase,
            "binding_phase_reason": asset.binding_phase_reason,
            "deadline_year": asset.statutory_deadline_year,
            "slack_formula": "slack = statutory_deadline - (today + Y)",
            "slack_months": asset.slack_months,
            "interpretation": (
                f"Starting migration today, this asset misses its {asset.statutory_deadline_year} "
                f"milestone by {abs(asset.slack_months):.1f} months."
                if asset.slack_months < 0
                else f"{asset.slack_months:.1f} months of slack remain against the "
                     f"{asset.statutory_deadline_year} milestone."
            ),
        },
        "priority": {
            "rank": asset.priority_rank,
            "risk_level": asset.risk_level,
            "rule": "Negative slack first, most negative first; then QIRS descending.",
        },
    }
