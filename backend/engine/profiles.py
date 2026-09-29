"""Enterprise profiles — the fit layer.

WHY THIS EXISTS
---------------
A cryptographic estate is not generic. A payments processor's estate is HSMs,
PIN keys, EMV tokenisation and a PCI audit; an ERP landscape is SAP
CommonCryptoLib, SNC, SSF and a dozen system-to-system trust relationships; a
manufacturer's is firmware signing keys burned into devices that will be in the
field for fifteen years. The *same scanner* pointed at these three produces three
completely different pictures, and a tool that treats them identically will be
confidently wrong about all of them.

So the engine carries a profile of what each kind of organisation *should* look
like, and reports the estate **relative to that expectation**:

  * which sensors this kind of enterprise cannot be inventoried without
  * which asset classes should be present, and roughly in what proportion
  * which regulations set its deadlines
  * which blind spots are merely inconvenient, and which are disqualifying

This turns "we found 195 assets" into "we found 195 assets, but for a payments
processor we would expect an HSM sensor and there isn't one, so the PIN and key
management estate is entirely unmeasured — this inventory is not audit-ready."

That second sentence is the product. The first is a file listing.

DESIGN NOTES
------------
Profiles are stated expectations, exactly like the QIRS policy inputs: every
entry carries a rationale, and an operator is expected to override them. They are
not learned, not inferred, and not derived from customer data.

The composition figures are order-of-magnitude expectations used to flag
*absence*, not to grade an estate. An estate with no code-signing keys at a
software vendor is a finding; an estate with 12% instead of 15% is noise.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class SensorExpectation:
    """A sensor this kind of enterprise needs, and how badly."""

    plugin_id: str
    criticality: str  # required | important | optional
    reason: str


@dataclass(frozen=True)
class EnterpriseProfile:
    """What an estate of this kind is expected to contain."""

    key: str
    label: str
    summary: str
    #: Sensors, and what it means when they are missing.
    sensors: list[SensorExpectation]
    #: asset_class -> expected share of the estate (0-1), order of magnitude.
    composition: dict[str, float]
    #: Asset classes whose complete absence is itself a finding.
    must_be_present: list[str]
    regulations: list[str]
    #: The estate characteristics that make this vertical hard.
    hard_parts: list[str]
    #: The sentence that opens a conversation with this buyer.
    lead_with: str


# --------------------------------------------------------------------------
# The profiles
#
# Sources for the expectations are the public standards each vertical is bound
# by (PCI DSS/PIN/P2PE, RBI, DPDP, IEC 62443, HIPAA, GSMA) and vendor
# documentation for the platforms each runs. Nothing here is derived from any
# customer's data.
# --------------------------------------------------------------------------

PROFILES: dict[str, EnterpriseProfile] = {
    "payments": EnterpriseProfile(
        key="payments",
        label="Payments / PSP / acquirer",
        summary=(
            "Card and real-time payment processing. The estate is dominated by "
            "hardware-resident keys under a compliance regime that already "
            "requires a documented key inventory."
        ),
        sensors=[
            SensorExpectation(
                "hsm_pkcs11", "required",
                "PIN, EMV and P2PE keys live inside HSMs. Without this sensor the "
                "highest-value half of a payments estate is entirely unmeasured, "
                "and PCI DSS already requires the inventory.",
            ),
            SensorExpectation(
                "tls", "required",
                "Acquirer, scheme and partner links are the harvest-now surface "
                "and change most often.",
            ),
            SensorExpectation(
                "key_material", "important",
                "Test keys and partner certificates leak into repositories; a "
                "reused key across settlement hosts is a systemic finding.",
            ),
            SensorExpectation(
                "cloud_kms", "important",
                "Tokenisation vaults and data-at-rest keys increasingly sit in "
                "cloud KMS rather than on-premises HSMs.",
            ),
            SensorExpectation(
                "config", "optional",
                "Edge TLS policy, largely confirmatory once the probe runs.",
            ),
        ],
        composition={
            "payment_hsm": 0.18,
            "tls_certificate": 0.30,
            "tls_key_exchange": 0.14,
            "token_signing": 0.10,
            "issuing_ca": 0.05,
            "root_ca": 0.02,
            "database_tls": 0.09,
            "vpn_ipsec": 0.06,
        },
        must_be_present=["payment_hsm", "token_signing"],
        regulations=[
            "PCI DSS 4.0 (documented key and certificate inventory, custodians)",
            "PCI PIN / P2PE (HSM-resident key handling)",
            "RBI Q-SAFE (CBOM-based sector diagnostic, India)",
            "DPDP Act 2023 (India, personal data)",
        ],
        hard_parts=[
            "HSM keys cannot migrate ahead of vendor firmware; the constraint is "
            "external and must be tracked, not scheduled.",
            "Scheme and partner links cannot be rotated unilaterally — every "
            "counterparty must move in step.",
            "Zero tolerance for settlement downtime, so previewing a change matters "
            "more than change speed.",
        ],
        lead_with=(
            "PCI DSS already requires you to document every key and its custodian. "
            "Most teams satisfy that with a spreadsheet that was true once. "
            "What would it take to make it continuously true — and to know which "
            "of those keys your HSM vendor cannot make quantum-safe yet?"
        ),
    ),
    "banking": EnterpriseProfile(
        key="banking",
        label="Bank / financial institution",
        summary=(
            "Core banking, payments and customer channels, with a long tail of "
            "legacy platforms and a regulator taking active interest."
        ),
        sensors=[
            SensorExpectation(
                "hsm_pkcs11", "required",
                "Core banking and payment keys are HSM-resident.",
            ),
            SensorExpectation(
                "tls", "required",
                "Channel and interbank connectivity; the largest changeable surface.",
            ),
            SensorExpectation(
                "kmip", "important",
                "Enterprise key managers hold the objects the HSM does not.",
            ),
            SensorExpectation(
                "source", "important",
                "Decades of in-house applications with hardcoded algorithm choices.",
            ),
            SensorExpectation(
                "key_material", "important",
                "Long-lived internal PKI material spread across build systems.",
            ),
        ],
        composition={
            "tls_certificate": 0.32,
            "tls_key_exchange": 0.15,
            "payment_hsm": 0.10,
            "database_tls": 0.12,
            "issuing_ca": 0.05,
            "root_ca": 0.02,
            "token_signing": 0.08,
            "vpn_ipsec": 0.07,
            "backup_encryption": 0.05,
        },
        must_be_present=["root_ca", "backup_encryption"],
        regulations=[
            "RBI Q-SAFE committee (CBOM diagnostic, phased transition)",
            "RBI cyber security framework / IT governance directions",
            "PCI DSS 4.0 where card data is processed",
            "DPDP Act 2023",
        ],
        hard_parts=[
            "Mainframe and core-banking cryptography is often out of reach of any "
            "scanner and must be captured by declaration.",
            "Archived data under long statutory retention is the worst "
            "harvest-now-decrypt-later exposure in any vertical.",
            "Change windows are quarterly at best.",
        ],
        lead_with=(
            "Your archives are the problem nobody costs. Data you are legally "
            "required to retain for ten years, encrypted with a key that is "
            "breakable in eight, is already lost — and it is the one exposure "
            "that migrating the front door does not fix."
        ),
    ),
    "erp": EnterpriseProfile(
        key="erp",
        label="ERP landscape (SAP and equivalents)",
        summary=(
            "A dense mesh of system-to-system trust inside one vendor's crypto "
            "stack, where the library version is the single most decisive fact."
        ),
        sensors=[
            SensorExpectation(
                "config", "required",
                "SNC, SSF and TLS parameters are configuration-defined per system; "
                "this is where an ERP landscape's cryptography actually lives.",
            ),
            SensorExpectation(
                "key_material", "required",
                "PSEs and system certificates; the trust between systems is the "
                "estate.",
            ),
            SensorExpectation(
                "tls", "important",
                "Front-door and integration endpoints.",
            ),
            SensorExpectation(
                "source", "optional",
                "Custom ABAP and extensions, a smaller surface than in-house shops.",
            ),
        ],
        composition={
            "tls_certificate": 0.34,
            "token_signing": 0.16,
            "database_tls": 0.14,
            "issuing_ca": 0.08,
            "root_ca": 0.03,
            "config": 0.15,
            "backup_encryption": 0.05,
        },
        must_be_present=["token_signing", "issuing_ca"],
        regulations=[
            "SOX / financial reporting integrity",
            "GDPR / DPDP for personal data in HR and CRM modules",
            "Sector rules inherited from the operator's own industry",
        ],
        hard_parts=[
            "The crypto library version differs per system and decides whether a "
            "system can do hybrid PQC at all — and nobody has that list.",
            "System-to-system trust means rotating one certificate can halt "
            "interfaces across the landscape.",
            "Upgrade windows are governed by the ERP release calendar, not by "
            "security.",
        ],
        lead_with=(
            "SAP already ships quantum-safe TLS in CommonCryptoLib 8.6 — hybrid "
            "X25519MLKEM768. So the question is not whether the vendor is ready. "
            "It is: which of your systems are on 8.6, which are three versions "
            "behind, and what breaks when the trust between them changes? "
            "Nobody has that inventory."
        ),
    ),
    "saas": EnterpriseProfile(
        key="saas",
        label="SaaS / technology company",
        summary=(
            "Cloud-native, code-heavy, fast-moving. The estate is mostly ephemeral "
            "and mostly defined in repositories and cloud APIs."
        ),
        sensors=[
            SensorExpectation(
                "source", "required",
                "Cryptography is chosen in code and changes weekly.",
            ),
            SensorExpectation(
                "key_material", "required",
                "Secret sprawl across repositories and CI is the dominant risk; "
                "internal repos are the more exposed ones.",
            ),
            SensorExpectation(
                "cloud_kms", "required",
                "Nearly all managed keys live in a cloud KMS.",
            ),
            SensorExpectation(
                "tls", "important",
                "Public endpoints, mostly automated already.",
            ),
        ],
        composition={
            "tls_certificate": 0.26,
            "tls_key_exchange": 0.14,
            "token_signing": 0.18,
            "code_signing": 0.10,
            "database_tls": 0.12,
            "generic_key": 0.12,
            "ssh_key": 0.05,
        },
        must_be_present=["code_signing", "token_signing"],
        regulations=[
            "SOC 2 / ISO 27001 (customer-driven)",
            "Customer contractual crypto requirements",
            "DPDP / GDPR by data residency",
        ],
        hard_parts=[
            "Ephemeral infrastructure means the inventory is stale within hours "
            "unless discovery is continuous.",
            "Code-signing keys outlive every other asset and are rarely owned.",
        ],
        lead_with=(
            "Your certificates rotate themselves. Your signing keys do not — and "
            "they are trusted by every artefact you have ever shipped."
        ),
    ),
    "industrial": EnterpriseProfile(
        key="industrial",
        label="Manufacturing / critical infrastructure / OT",
        summary=(
            "Long-lived devices in the field, firmware trust anchors, and a "
            "replacement cycle measured in decades."
        ),
        sensors=[
            SensorExpectation(
                "key_material", "required",
                "Firmware and device signing keys are the estate's centre of "
                "gravity.",
            ),
            SensorExpectation(
                "source", "important",
                "Embedded code with pinned algorithm choices.",
            ),
            SensorExpectation(
                "config", "important",
                "Gateway and historian configuration.",
            ),
            SensorExpectation(
                "tls", "optional",
                "Much of the estate is not IP-reachable for probing.",
            ),
        ],
        composition={
            "firmware_signing": 0.16,
            "device_identity": 0.24,
            "code_signing": 0.08,
            "tls_certificate": 0.20,
            "root_ca": 0.03,
            "config": 0.14,
            "vpn_ipsec": 0.08,
        },
        must_be_present=["firmware_signing", "device_identity"],
        regulations=[
            "IEC 62443 (industrial automation security)",
            "NIS2 / national critical infrastructure rules",
            "Sector regulator directions",
        ],
        hard_parts=[
            "A trust anchor burned in at manufacture cannot be rotated in "
            "software; migration is a hardware refresh programme.",
            "Availability outranks confidentiality, so change is resisted by "
            "policy, not just by inertia.",
        ],
        lead_with=(
            "Your firmware signing key is trusted by every device you have ever "
            "shipped, for as long as it is in service. It is the one asset a "
            "confidentiality-only risk model scores at almost zero — and the one "
            "you cannot fix with a software change."
        ),
    ),
    "healthcare": EnterpriseProfile(
        key="healthcare",
        label="Healthcare / life sciences",
        summary=(
            "Very long data retention, connected medical devices, and privacy "
            "regulation with real penalties."
        ),
        sensors=[
            SensorExpectation(
                "tls", "required",
                "Clinical system integration is the interceptable surface.",
            ),
            SensorExpectation(
                "key_material", "required",
                "Device identities and integration certificates.",
            ),
            SensorExpectation(
                "config", "important",
                "Interface engines and legacy clinical systems.",
            ),
            SensorExpectation(
                "cloud_kms", "important",
                "Imaging and records archives at rest.",
            ),
        ],
        composition={
            "tls_certificate": 0.30,
            "device_identity": 0.16,
            "database_tls": 0.14,
            "backup_encryption": 0.14,
            "firmware_signing": 0.06,
            "token_signing": 0.08,
            "vpn_ipsec": 0.06,
        },
        must_be_present=["backup_encryption", "device_identity"],
        regulations=[
            "HIPAA (US) / DPDP Act 2023 (India)",
            "Medical device regulation (FDA premarket cyber, EU MDR)",
            "Records retention statutes measured in decades",
        ],
        hard_parts=[
            "Patient records are retained for a lifetime, which is the longest "
            "confidentiality horizon of any vertical.",
            "Medical devices cannot be patched on a security schedule.",
        ],
        lead_with=(
            "A record you must keep for the patient's lifetime, encrypted with a "
            "key that has an eight-year horizon, is already a breach with a "
            "delayed disclosure date."
        ),
    ),
    "telecom": EnterpriseProfile(
        key="telecom",
        label="Telecommunications operator",
        summary=(
            "Subscriber identity, interconnect and transport at national scale, "
            "on hardware with a replacement cycle measured in decades, and the "
            "only sector with a published PQC use-case standard of its own."
        ),
        sensors=[
            SensorExpectation(
                "hsm_pkcs11", "required",
                "Subscriber credential and interconnect keys are HSM-resident; "
                "SIM provisioning depends on them.",
            ),
            SensorExpectation(
                "tls", "required",
                "Interconnect, roaming and API surfaces - the interceptable bulk "
                "of the estate.",
            ),
            SensorExpectation(
                "config", "important",
                "Core network elements are configuration-defined and rarely "
                "re-examined once in service.",
            ),
            SensorExpectation(
                "key_material", "important",
                "Long-lived network element identities spread across OSS/BSS.",
            ),
        ],
        composition={
            "tls_certificate": 0.26,
            "tls_key_exchange": 0.14,
            "device_identity": 0.20,
            "payment_hsm": 0.06,
            "vpn_ipsec": 0.12,
            "config": 0.12,
            "root_ca": 0.02,
        },
        must_be_present=["device_identity", "vpn_ipsec"],
        regulations=[
            "GSMA PQ.03 - PQC Guidelines for Telecom Use Cases",
            "National telecom licensing and lawful-intercept obligations",
            "NIS2 / critical infrastructure directives where applicable",
        ],
        hard_parts=[
            "Network hardware lifecycles run to a decade or more, so a large "
            "share of the estate cannot be migrated on any security schedule.",
            "Roaming and interconnect are multilateral: no operator can change "
            "a trust relationship unilaterally.",
            "Subscriber credentials are provisioned into SIMs at manufacture.",
        ],
        lead_with=(
            "GSMA has already written the standard for your sector - PQ.03 names "
            "cryptographic inventory as the first workstream. The question is "
            "whether you can produce that inventory across a network whose "
            "hardware predates the standard by a decade."
        ),
    ),
    "energy": EnterpriseProfile(
        key="energy",
        label="Energy / utility operator",
        summary=(
            "Generation, transmission and metering, where availability outranks "
            "everything and the regulator has flagged quantum without yet "
            "mandating anything."
        ),
        sensors=[
            SensorExpectation(
                "config", "required",
                "Substation and control-system configuration is where the "
                "cryptography is actually declared.",
            ),
            SensorExpectation(
                "key_material", "required",
                "Device identities and firmware signing keys for field assets.",
            ),
            SensorExpectation(
                "tls", "important",
                "Corporate and market-facing systems; much of OT is not "
                "IP-reachable for probing.",
            ),
            SensorExpectation(
                "runtime_trace", "optional",
                "Rarely permitted on operational technology, and correctly so.",
            ),
        ],
        composition={
            "device_identity": 0.28,
            "firmware_signing": 0.12,
            "config": 0.18,
            "tls_certificate": 0.18,
            "vpn_ipsec": 0.10,
            "root_ca": 0.03,
            "backup_encryption": 0.05,
        },
        must_be_present=["device_identity", "firmware_signing"],
        regulations=[
            "NERC CIP - quantum listed as an Emerging Security Risk (Jan 2026 roadmap), no mandate yet",
            "IEC 62443 for industrial automation and control",
            "National critical-infrastructure directives",
        ],
        hard_parts=[
            "Field devices are commissioned for 15-25 years and cannot be "
            "patched on a security cadence.",
            "Availability and safety outrank confidentiality by regulation, so "
            "change windows are rare and heavily controlled.",
            "No PQC mandate exists yet, which makes budget hard to obtain and "
            "makes early inventory a competitive advantage rather than a cost.",
        ],
        lead_with=(
            "NERC's 2026 CIP roadmap lists quantum as an emerging risk and stops "
            "short of a requirement. That gap is the whole opportunity: the "
            "inventory takes two years and the mandate will not wait for you to "
            "start it."
        ),
    ),
    "government": EnterpriseProfile(
        key="government",
        label="Government / public sector",
        summary=(
            "The only sector with hard, dated, binding migration deadlines and a "
            "procurement rule that pushes them down the supply chain."
        ),
        sensors=[
            SensorExpectation(
                "tls", "required",
                "Citizen-facing and inter-agency services, the measurable surface.",
            ),
            SensorExpectation(
                "key_material", "required",
                "Agency PKI and signing material underpinning identity.",
            ),
            SensorExpectation(
                "source", "important",
                "Bespoke systems with long service lives and hardcoded algorithms.",
            ),
            SensorExpectation(
                "hsm_pkcs11", "important",
                "National identity and signing keys are hardware-resident.",
            ),
        ],
        composition={
            "tls_certificate": 0.30,
            "token_signing": 0.14,
            "issuing_ca": 0.08,
            "root_ca": 0.04,
            "database_tls": 0.12,
            "backup_encryption": 0.10,
            "source": 0.12,
        },
        must_be_present=["root_ca", "token_signing"],
        regulations=[
            "US EO 14412 (Jun 2026) - accelerated federal PQC migration, binding deadlines for high-value assets",
            "CNSA 2.0 - new NSS acquisitions quantum-resistant from 2027",
            "NIST IR 8547 - quantum-vulnerable algorithms deprecated 2030, disallowed 2035",
            "FAR contractor compliance rules flowing to suppliers",
        ],
        hard_parts=[
            "Deadlines are statutory, not advisory, and slip is a finding.",
            "Records retention runs to decades, so harvest-now exposure is "
            "already accrued on anything transmitted today.",
            "Procurement rules push the same obligation onto every supplier, "
            "multiplying the coordination problem.",
        ],
        lead_with=(
            "Yours is the only sector where the dates are already law. NIST "
            "deprecates the algorithms you run in 2030 and disallows them in "
            "2035, and the FAR is pushing that onto your suppliers too. The "
            "question is whether your inventory can survive an audit, not "
            "whether you will migrate."
        ),
    ),
}



DEFAULT_PROFILE = "payments"


def get_profile(key: str) -> EnterpriseProfile:
    return PROFILES.get(key, PROFILES[DEFAULT_PROFILE])


def list_profiles() -> list[dict]:
    """Summary cards for the profile picker."""
    return [
        {
            "key": p.key,
            "label": p.label,
            "summary": p.summary,
            "required_sensors": [s.plugin_id for s in p.sensors if s.criticality == "required"],
            "regulations": p.regulations,
            "lead_with": p.lead_with,
        }
        for p in PROFILES.values()
    ]


def fit_report(profile_key: str, plugin_states: dict[str, bool], assets: list) -> dict:
    """How well this deployment fits this kind of enterprise.

    `plugin_states` maps plugin_id -> currently available. `assets` is the scored
    estate (may be empty).

    The headline is `audit_ready`: whether the sensors a *required* by this
    vertical are actually running. An estate missing a required sensor is not a
    partial inventory, it is an inventory with a hole in the most important
    place, and saying so is the whole point of this module.
    """
    profile = get_profile(profile_key)

    sensors = []
    missing_required: list[str] = []
    for expectation in profile.sensors:
        active = bool(plugin_states.get(expectation.plugin_id, False))
        if expectation.criticality == "required" and not active:
            missing_required.append(expectation.plugin_id)
        sensors.append(
            {
                "plugin_id": expectation.plugin_id,
                "criticality": expectation.criticality,
                "reason": expectation.reason,
                "active": active,
            }
        )

    required_total = sum(1 for s in profile.sensors if s.criticality == "required")
    required_active = required_total - len(missing_required)
    coverage_pct = round(100.0 * required_active / required_total, 1) if required_total else 100.0

    # Composition: which expected classes are entirely absent.
    observed: dict[str, int] = {}
    for asset in assets:
        cls = getattr(asset, "asset_class", None)
        if cls:
            observed[cls] = observed.get(cls, 0) + 1

    total = len(assets) or 1
    composition = []
    for cls, expected_share in sorted(
        profile.composition.items(), key=lambda kv: kv[1], reverse=True
    ):
        count = observed.get(cls, 0)
        composition.append(
            {
                "asset_class": cls,
                "expected_share": round(expected_share, 3),
                "observed_share": round(count / total, 3),
                "observed_count": count,
                "absent": count == 0,
            }
        )

    absent_but_required = [
        cls for cls in profile.must_be_present if observed.get(cls, 0) == 0
    ]

    return {
        "profile": {
            "key": profile.key,
            "label": profile.label,
            "summary": profile.summary,
            "regulations": profile.regulations,
            "hard_parts": profile.hard_parts,
            "lead_with": profile.lead_with,
        },
        "sensors": sensors,
        "required_sensor_coverage_pct": coverage_pct,
        "missing_required_sensors": missing_required,
        "composition": composition,
        "asset_classes_absent_but_expected": absent_but_required,
        "audit_ready": not missing_required and not absent_but_required,
        "verdict": _verdict(profile, missing_required, absent_but_required, bool(assets)),
    }


#: Letters whose *spoken name* begins with a vowel sound, for initialisms read
#: letter by letter ("an ERP", "an HSM", "an SLA").
_LETTER_NAME_VOWELS = set("AEFHILMNORSX")


def _article(label: str) -> str:
    """'a' or 'an', chosen by how the label is actually said aloud.

    Two different rules, because two different kinds of word appear here:

      * an initialism read letter by letter ("ERP" -> "ee-arr-pee") takes the
        article for its first letter's *name*, giving "an ERP landscape";
      * an ordinary word - including an acronym pronounced as a word, like
        "SaaS" -> "sass" - takes the plain vowel rule, giving "a SaaS company".

    Profile labels are operator-facing prose, and "a ERP landscape" or
    "an SaaS company" in a verdict an executive reads is the kind of detail
    that costs credibility for free.
    """
    first = label.split()[0] if label.split() else label
    word = "".join(ch for ch in first if ch.isalpha())
    if not word:
        return "a"

    # Read letter by letter only when every letter is upper case, which is what
    # separates "ERP" from "SaaS".
    if len(word) > 1 and word.isupper():
        return "an" if word[0] in _LETTER_NAME_VOWELS else "a"

    return "an" if word[0].upper() in "AEIOU" else "a"


def _verdict(
    profile: EnterpriseProfile,
    missing_required: list[str],
    absent_classes: list[str],
    has_assets: bool,
) -> str:
    """One sentence an executive can act on."""
    label = profile.label
    article = _article(label)

    if not has_assets:
        return "No estate loaded, so fit cannot be assessed."
    if missing_required:
        names = ", ".join(missing_required)
        return (
            f"Not audit-ready for {article} {label}: the required "
            f"sensor(s) {names} are not connected, so part of the estate that "
            f"this vertical is judged on has not been measured."
        )
    if absent_classes:
        names = ", ".join(absent_classes)
        return (
            f"Sensors are connected, but no {names} assets were found. For "
            f"{article} {label} that absence is itself a finding — either "
            f"the inventory is incomplete or those assets are unmanaged."
        )
    return (
        f"Coverage matches what {article} {label} is expected to have. "
        f"The inventory can be defended against {profile.regulations[0]}."
    )
