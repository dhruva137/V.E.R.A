"""CycloneDX 1.7 / 1.6 CBOM validator.

Two layers. First, the document is validated against the **official CycloneDX
JSON schema** for its specVersion, vendored under `engine/schemas/` so it runs
offline (`engine.schema_validation`). Second, rules a JSON schema cannot
express are checked natively, chiefly that every reference resolves to a
component that exists. Each rule reports pass/fail and the offending bom-refs.
JSON only: the 1.7 JSON schema and XSD disagree on `protocolProperties`
(CycloneDX issue #1030), so no XML validity is claimed.

What is checked, per rule, with a pass/fail and the offending bom-refs:

  - the official JSON schema for the document's specVersion
  - document envelope: bomFormat, specVersion, serialNumber URN form, version
  - metadata: timestamp in RFC 3339, tools, target component
  - every component: required fields, type, unique bom-ref
  - assetType against the 1.6 enum
  - the property object required by each assetType is present, and no component
    carries a property object belonging to a different assetType
  - every nested enum: primitive, cryptoFunctions, executionEnvironment,
    implementationPlatform, mode, padding, relatedCryptoMaterial type,
    protocol type, certificationLevel
  - nistQuantumSecurityLevel in range 0-6
  - referential integrity: every algorithmRef, signatureAlgorithmRef,
    subjectPublicKeyRef, cryptoRefArray entry and dependsOn target resolves to a
    component that exists
  - date fields parse as RFC 3339
"""

from __future__ import annotations

import datetime
import re
from dataclasses import dataclass, field

from engine.cbom import (
    ASSET_TYPES,
    CRYPTO_FUNCTIONS,
    EXECUTION_ENVIRONMENTS,
    IMPLEMENTATION_PLATFORMS,
    MODES,
    PADDINGS,
    PRIMITIVES,
    PROTOCOL_TYPES,
    RELATED_MATERIAL_TYPES,
    SPEC_VERSION,
    SUPPORTED_SPECS,
)
from engine.schema_validation import validate_cyclonedx

_URN_UUID = re.compile(
    r"^urn:uuid:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

# Which property object each assetType requires, and therefore which ones are
# wrong to carry. Putting algorithmProperties on a protocol asset is the single
# most common way a hand-rolled CBOM fails.
_REQUIRED_PROPERTY_OBJECT = {
    "algorithm": "algorithmProperties",
    "certificate": "certificateProperties",
    "protocol": "protocolProperties",
    "related-crypto-material": "relatedCryptoMaterialProperties",
}

_ALL_PROPERTY_OBJECTS = set(_REQUIRED_PROPERTY_OBJECT.values())

_CERTIFICATION_LEVELS = {
    "none", "other", "unknown",
    *{f"fips140-{s}-l{level}" for s in (1, 2, 3) for level in range(1, 5)},
    *{f"cc-eal{n}" for n in range(1, 8)},
    *{f"cc-eal{n}+" for n in range(1, 8)},
}


@dataclass
class Rule:
    id: str
    description: str
    passed: bool = True
    violations: list[str] = field(default_factory=list)

    def fail(self, detail: str) -> None:
        self.passed = False
        # Cap the list: a systematically broken emitter would otherwise produce
        # thousands of identical lines and drown the report.
        if len(self.violations) < 25:
            self.violations.append(detail)

    def to_dict(self, total_violations: int | None = None) -> dict:
        return {
            "id": self.id,
            "description": self.description,
            "passed": self.passed,
            "violation_count": total_violations
            if total_violations is not None
            else len(self.violations),
            "violations": self.violations,
        }


def _is_rfc3339(value) -> bool:
    if not isinstance(value, str):
        return False
    try:
        datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
        return True
    except ValueError:
        return False


def validate_cbom(cbom: dict) -> dict:
    """Validate a CBOM and return a rule-by-rule report."""
    rules: list[Rule] = []
    counts: dict[str, int] = {}

    def rule(rule_id: str, description: str) -> Rule:
        r = Rule(rule_id, description)
        rules.append(r)
        counts[rule_id] = 0
        return r

    def record(r: Rule, detail: str) -> None:
        counts[r.id] += 1
        r.fail(detail)

    # --- Envelope -----------------------------------------------------------
    envelope = rule("envelope", "bomFormat, specVersion, serialNumber and version are well formed")
    spec = str(cbom.get("specVersion", ""))
    if cbom.get("bomFormat") != "CycloneDX":
        record(envelope, f"bomFormat is {cbom.get('bomFormat')!r}, expected 'CycloneDX'")
    if spec not in SUPPORTED_SPECS:
        record(envelope, f"specVersion is {cbom.get('specVersion')!r}, expected one of {SUPPORTED_SPECS}")

    # --- The official JSON schema (vendored, offline) -----------------------
    schema_rule = rule("official_schema", "the document validates against the official CycloneDX JSON schema")
    if spec in SUPPORTED_SPECS:
        for error in validate_cyclonedx(cbom, spec):
            record(schema_rule, f"{error['path']}: {error['message']}")
    serial = cbom.get("serialNumber", "")
    if not _URN_UUID.match(serial or ""):
        record(envelope, f"serialNumber {serial!r} is not a urn:uuid")
    if not isinstance(cbom.get("version"), int) or cbom.get("version", 0) < 1:
        record(envelope, f"version must be a positive integer, got {cbom.get('version')!r}")

    # --- Metadata -----------------------------------------------------------
    metadata_rule = rule("metadata", "metadata carries an RFC 3339 timestamp, tools and a target component")
    metadata = cbom.get("metadata") or {}
    if not _is_rfc3339(metadata.get("timestamp")):
        record(metadata_rule, f"metadata.timestamp {metadata.get('timestamp')!r} is not RFC 3339")
    if not metadata.get("tools"):
        record(metadata_rule, "metadata.tools is absent")
    if not (metadata.get("component") or {}).get("name"):
        record(metadata_rule, "metadata.component.name is absent")

    components = cbom.get("components")
    if not isinstance(components, list):
        components_rule = rule("components", "components is a list")
        record(components_rule, "components is missing or not a list")
        return _report(rules, counts, 0, spec)

    # --- Components ---------------------------------------------------------
    required = rule("component_required", "every component has a type (cryptographic-asset or library), a name and a bom-ref")
    unique = rule("bomref_unique", "bom-ref values are unique across the document")
    asset_type_rule = rule("asset_type", "cryptoProperties.assetType is in the 1.6 enum")
    property_object = rule(
        "property_object",
        "each assetType carries its own property object and no other",
    )
    primitive_rule = rule("primitive", "algorithmProperties.primitive is in the 1.6 enum")
    functions_rule = rule("crypto_functions", "algorithmProperties.cryptoFunctions are in the 1.6 enum")
    env_rule = rule("execution_env", "executionEnvironment and implementationPlatform are in the 1.6 enums")
    mode_rule = rule("mode_padding", "mode and padding are in the 1.6 enums")
    material_rule = rule("material_type", "relatedCryptoMaterialProperties.type is in the 1.6 enum")
    protocol_rule = rule("protocol_type", "protocolProperties.type is in the 1.6 enum")
    cert_level_rule = rule("certification_level", "certificationLevel entries are in the 1.6 enum")
    nist_rule = rule("nist_level", "nistQuantumSecurityLevel is an integer 0-6")
    dates_rule = rule("dates", "certificate and key-material dates are RFC 3339")
    refs_rule = rule("ref_integrity", "every bom-ref referenced by another component exists")

    seen: set[str] = set()
    all_refs: set[str] = set()

    for index, component in enumerate(components):
        label = component.get("bom-ref") or f"components[{index}]"

        kind = component.get("type")
        if kind not in ("cryptographic-asset", "library"):
            record(required, f"{label}: type is {kind!r}, expected 'cryptographic-asset' or 'library'")
        if not component.get("name"):
            record(required, f"{label}: name is absent")
        ref = component.get("bom-ref")
        if not ref:
            record(required, f"components[{index}]: bom-ref is absent")
        else:
            if ref in seen:
                record(unique, f"{ref}: duplicate bom-ref")
            seen.add(ref)
            all_refs.add(ref)

        if kind == "library":
            continue  # a crypto library carries no cryptoProperties; the official schema checks its shape
        crypto = component.get("cryptoProperties")
        if not isinstance(crypto, dict):
            record(asset_type_rule, f"{label}: cryptoProperties is absent")
            continue

        asset_type = crypto.get("assetType")
        if asset_type not in ASSET_TYPES:
            record(asset_type_rule, f"{label}: assetType {asset_type!r} is not in {sorted(ASSET_TYPES)}")
            continue

        expected_object = _REQUIRED_PROPERTY_OBJECT[asset_type]
        if expected_object not in crypto:
            record(property_object, f"{label}: assetType '{asset_type}' requires {expected_object}")
        for other in _ALL_PROPERTY_OBJECTS - {expected_object}:
            if other in crypto:
                record(
                    property_object,
                    f"{label}: assetType '{asset_type}' must not carry {other}",
                )

        algorithm = crypto.get("algorithmProperties") or {}
        if algorithm:
            primitive = algorithm.get("primitive")
            if primitive is not None and primitive not in PRIMITIVES:
                record(primitive_rule, f"{label}: primitive {primitive!r} is not in the enum")
            for function in algorithm.get("cryptoFunctions") or []:
                if function not in CRYPTO_FUNCTIONS:
                    record(functions_rule, f"{label}: cryptoFunction {function!r} is not in the enum")
            env = algorithm.get("executionEnvironment")
            if env is not None and env not in EXECUTION_ENVIRONMENTS:
                record(env_rule, f"{label}: executionEnvironment {env!r} is not in the enum")
            platform = algorithm.get("implementationPlatform")
            if platform is not None and platform not in IMPLEMENTATION_PLATFORMS:
                record(env_rule, f"{label}: implementationPlatform {platform!r} is not in the enum")
            mode = algorithm.get("mode")
            if mode is not None and mode not in MODES:
                record(mode_rule, f"{label}: mode {mode!r} is not in the enum")
            padding = algorithm.get("padding")
            if padding is not None and padding not in PADDINGS:
                record(mode_rule, f"{label}: padding {padding!r} is not in the enum")
            for level in algorithm.get("certificationLevel") or []:
                if level not in _CERTIFICATION_LEVELS:
                    record(cert_level_rule, f"{label}: certificationLevel {level!r} is not in the enum")
            nist = algorithm.get("nistQuantumSecurityLevel")
            if nist is not None and (not isinstance(nist, int) or not 0 <= nist <= 6):
                record(nist_rule, f"{label}: nistQuantumSecurityLevel {nist!r} is not an integer 0-6")

        material = crypto.get("relatedCryptoMaterialProperties") or {}
        if material:
            material_type = material.get("type")
            if material_type is not None and material_type not in RELATED_MATERIAL_TYPES:
                record(material_rule, f"{label}: relatedCryptoMaterial type {material_type!r} is not in the enum")
            for field_name in ("activationDate", "expirationDate", "creationDate"):
                value = material.get(field_name)
                if value is not None and not _is_rfc3339(value):
                    record(dates_rule, f"{label}: {field_name} {value!r} is not RFC 3339")

        certificate = crypto.get("certificateProperties") or {}
        if certificate:
            if not certificate.get("subjectName"):
                record(required, f"{label}: certificateProperties.subjectName is absent")
            for field_name in ("notValidBefore", "notValidAfter"):
                value = certificate.get(field_name)
                if value is not None and not _is_rfc3339(value):
                    record(dates_rule, f"{label}: {field_name} {value!r} is not RFC 3339")

        protocol = crypto.get("protocolProperties") or {}
        if protocol:
            protocol_type = protocol.get("type")
            if protocol_type is not None and protocol_type not in PROTOCOL_TYPES:
                record(protocol_rule, f"{label}: protocol type {protocol_type!r} is not in the enum")

    # --- Referential integrity ---------------------------------------------
    # Collected after the component pass so forward references are legal.
    referenced: list[tuple[str, str]] = []
    for index, component in enumerate(components):
        label = component.get("bom-ref") or f"components[{index}]"
        crypto = component.get("cryptoProperties") or {}
        material = crypto.get("relatedCryptoMaterialProperties") or {}
        certificate = crypto.get("certificateProperties") or {}
        protocol = crypto.get("protocolProperties") or {}

        for key in ("algorithmRef",):
            if material.get(key):
                referenced.append((label, material[key]))
        for key in ("signatureAlgorithmRef", "subjectPublicKeyRef"):
            if certificate.get(key):
                referenced.append((label, certificate[key]))
        for ref in protocol.get("cryptoRefArray") or []:
            referenced.append((label, ref))
        for suite in protocol.get("cipherSuites") or []:
            for ref in suite.get("algorithms") or []:
                referenced.append((label, ref))
        for transforms in (protocol.get("ikev2TransformTypes") or {}).values():
            for transform in transforms if isinstance(transforms, list) else []:
                if isinstance(transform, dict) and transform.get("algorithm"):
                    referenced.append((label, transform["algorithm"]))

    for dependency in cbom.get("dependencies") or []:
        origin = dependency.get("ref")
        if origin:
            referenced.append(("dependencies", origin))
        for ref in dependency.get("dependsOn") or []:
            referenced.append((origin or "dependencies", ref))

    for source, target in referenced:
        if target not in all_refs:
            record(refs_rule, f"{source}: references unknown bom-ref {target!r}")

    return _report(rules, counts, len(components), spec)


def _report(rules: list[Rule], counts: dict[str, int], component_count: int, spec: str = SPEC_VERSION) -> dict:
    checks = [r.to_dict(counts.get(r.id, len(r.violations))) for r in rules]
    failed = [c for c in checks if not c["passed"]]
    return {
        "valid": not failed,
        "spec_version": spec,
        "validator": ("Official CycloneDX JSON schema (vendored, offline) plus VERA referential-integrity "
                      "and cryptographic-asset rules"),
        "xml_validity_claimed": False,
        "components_checked": component_count,
        "rules_total": len(checks),
        "rules_passed": len(checks) - len(failed),
        "rules_failed": len(failed),
        "total_violations": sum(c["violation_count"] for c in checks),
        "checks": checks,
    }


def validate_cbom_bool(cbom: dict) -> bool:
    """Convenience wrapper for callers that only need pass/fail."""
    return validate_cbom(cbom)["valid"]
