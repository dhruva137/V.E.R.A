"""Discovery surface — registers every sensor and reports estate coverage.

This module is the single place that knows which sensors exist. Adding a source
(PKCS#11, KMIP, cloud KMS, an eBPF agent) means registering a plugin here; no
scan path, route, or UI needs to change, because everything downstream reads the
registry rather than a hardcoded list.

The plugins registered today fall into three availability classes:

  * **Always available** — pure local analysis (source, configuration, key
    material in a tree). No credentials, no network.
  * **Available on demand** — needs a target (TLS endpoints to probe).
  * **Registered but unconfigured for live** — enterprise connectors (HSM over
    PKCS#11, key managers over KMIP, cloud KMS, runtime tracing). When a
    demo/vault file dump is present they are *measurable via file dump*; live
    collection without credentials remains a stated blind spot. An inventory
    that silently omits the HSM is worse than one that says "the HSM was
    never asked".

That last class is deliberate and honest. A registered-but-unconfigured plugin
is a documented gap in coverage, not a missing feature pretending not to exist.
"""

from __future__ import annotations

from adapters import describe_adapters
from adapters.cloud_kms import coverage_contract as cloud_kms_contract
from adapters.kmip import coverage_contract as kmip_contract
from adapters.keystore import coverage_contract as keystore_contract
from adapters.pkcs11 import coverage_contract as pkcs11_contract
from adapters.tls import coverage_contract as tls_contract
from collectors import (
    config_scanner,
    secret_scanner,
    source_scanner,
    tls_scanner,
    vault_collector,
)
from collectors.registry import REGISTRY as COLLECTORS
from engine.plugins import REGISTRY, FunctionPlugin, PluginRegistry


def _tuple_head(fn):
    """Adapt collectors that return (findings, errors) to return findings."""

    def wrapped(**kwargs):
        result = fn(**kwargs)
        if isinstance(result, tuple):
            return result[0]
        return result

    return wrapped


def _collector(name: str):
    """A plugin function that runs one contract collector over `root`."""

    def run(**kwargs):
        return COLLECTORS[name].collect([str(kwargs.get("root", "."))]).findings

    return run


def _vault_availability() -> tuple[bool, str]:
    """The vault sensor is available when a vault directory is readable.

    Stated as a reason rather than a silent absence: "no vault is configured"
    is a coverage gap the operator needs to see, because the assets it would
    have found are the ones with the worst timelines in the estate.
    """
    if vault_collector.DEFAULT_VAULT.is_dir():
        return True, ""
    return False, (
        "No key-manager metadata directory found. Point VERA_VAULT_DIR at a "
        "PKCS#11/KMIP/cloud-KMS metadata export, or connect a live key manager."
    )


def _unconfigured(what: str):
    """Availability check for a connector that needs credentials it does not have."""

    def check() -> tuple[bool, str]:
        return False, f"Not configured. {what}"

    return check


def _adapter_measurement(adapter_id: str):
    """Lazy measurement card from the adapter catalog (file dump vs live)."""

    def check():
        for card in describe_adapters():
            if card["id"] == adapter_id:
                return card["measurement"]
        return None

    return check


def _live_blind_spot(adapter_id: str, live_requirement: str):
    """Live path stays unavailable; reason mentions file dump when present."""

    def check() -> tuple[bool, str]:
        measurement = _adapter_measurement(adapter_id)()
        live = f"Live path not configured. {live_requirement}"
        if measurement and measurement.get("mode") == "file_dump":
            files = ", ".join(measurement.get("vault_files_present") or [])
            return False, (
                f"{live} Measurable via file dump"
                + (f" ({files})." if files else ".")
            )
        return False, live

    return check


def register_builtins(registry: PluginRegistry = REGISTRY) -> PluginRegistry:
    """Populate the registry. Idempotent — safe to call more than once."""
    if registry.all():
        return registry

    # --- Local analysis: always available ---------------------------------
    registry.register(
        FunctionPlugin(
            id="source",
            name="Source code analysis",
            provenance="static_analysis",
            zone="repository",
            description=(
                "Matches cryptographic API call sites in Python, Java, Go, C/C++, "
                "JavaScript/TypeScript, Rust and C# with tree-sitter. Finds where "
                "cryptography is written, not whether it runs."
            ),
            fn=_tuple_head(source_scanner.scan_source),
        )
    )

    registry.register(
        FunctionPlugin(
            id="key_material",
            name="Key material scanner",
            provenance="artifact_parsed",
            zone="repository",
            description=(
                "Finds PEM private keys, certificates and hardcoded credentials in "
                "a tree. Retains a SHA-256 fingerprint only — never the key."
            ),
            fn=lambda **kw: secret_scanner.scan_tree(kw.get("root", ".")),
        )
    )

    registry.register(
        FunctionPlugin(
            id="config",
            name="Configuration analysis",
            provenance="config_parsed",
            zone="host",
            description=(
                "Reads protocol and cipher directives from server configuration. "
                "Accurate about intent; the running process may differ."
            ),
            fn=_tuple_head(config_scanner.scan_configs),
        )
    )

    # --- Built artefacts: what ships, not what was written -----------------
    #
    # These wrap the collector-contract collectors (collectors/registry.py), so
    # the radar and the full-scan job run the same code on the same target.
    for plugin_id, name, provenance, zone, description in (
        ("dependency", "Dependencies and runtimes", "artifact_parsed", "repository",
         "Reads lockfiles and package databases in nine ecosystems and names the first "
         "release of each crypto library with native ML-KEM / ML-DSA."),
        ("binary", "Binaries and shared libraries", "artifact_parsed", "host",
         "Parses ELF, PE, Mach-O and JAR files: imported crypto symbols, version banners, "
         "embedded algorithm constants and certificates."),
        ("container", "Container images", "artifact_parsed", "image",
         "Walks OCI and Docker image layers with whiteouts, and says whether a finding "
         "sits in the base image or the application layer."),
        ("capture", "Recorded handshakes", "runtime_observed", "network",
         "Replays recorded TLS and SSH observations from a capture export."),
    ):
        registry.register(
            FunctionPlugin(
                id=plugin_id, name=name, provenance=provenance, zone=zone, description=description,
                fn=_collector(plugin_id),
            )
        )

    registry.register(
        FunctionPlugin(
            id="ssh",
            name="SSH endpoint probe",
            provenance="runtime_observed",
            zone="network",
            description=(
                "Reads the server banner and key-exchange offer from an SSH server. "
                "Sends only an identification line; never authenticates."
            ),
            fn=lambda **kw: COLLECTORS["ssh"].collect(list(kw.get("targets") or [])).findings,
            availability=lambda: (False, "Needs an operator-named host to probe."),
        )
    )

    # --- Key managers: the systems of record for the keys that matter -----
    #
    # Reads native PKCS#11 / KMIP / cloud-KMS metadata shapes. `declared`
    # rather than `runtime_observed`: the HSM is authoritative about what it
    # holds, but holding a key is not proof anything calls it.
    registry.register(
        FunctionPlugin(
            id="key_vault",
            name="Key manager metadata (PKCS#11 / KMIP / cloud KMS)",
            provenance="declared",
            zone="key-manager",
            description=(
                "Enumerates key objects and their attributes from HSM slots, "
                "KMIP managed objects and cloud KMS, and reads each token's "
                "mechanism list to establish PQC firmware readiness. Metadata "
                "only — every private object is non-extractable by design. "
                "Runs the five adapters against a vault directory when present."
            ),
            fn=lambda **kw: vault_collector.scan_vault(kw.get("vault_root"))[0],
            availability=_vault_availability,
        )
    )

    # --- Network: available when given a target ---------------------------
    registry.register(
        FunctionPlugin(
            id="tls",
            name="TLS endpoint probe",
            provenance="runtime_observed",
            zone="network",
            description=(
                "Completes a real handshake and reads the negotiated protocol, "
                "cipher suite, key-exchange group and certificate chain. The only "
                "sensor here that proves cryptography is actually in use."
            ),
            fn=_tuple_head(tls_scanner.scan_tls_endpoints),
            coverage_contract=tls_contract(),
            measurement=_adapter_measurement("tls"),
        )
    )

    # --- Adapter-backed enterprise connectors -----------------------------
    #
    # Live collection needs credentials this process does not have, so
    # `available` stays False (honest blind spot). When demo/vault files exist,
    # measurement_mode is file_dump — measurable without pretending to be a
    # live Active connector or inventing asset counts.
    for spec in (
        (
            "hsm_pkcs11",
            "pkcs11",
            "HSM (PKCS#11)",
            "declared",
            "hsm",
            "Enumerates key objects and their attributes from an HSM, and reads the "
            "supported mechanism list to determine post-quantum firmware readiness. "
            "Never extracts key material — the HSM refuses, by design.",
            "Provide a PKCS#11 module path and a read-only slot credential.",
            pkcs11_contract,
        ),
        (
            "kmip",
            "kmip",
            "Key manager (KMIP)",
            "declared",
            "key-manager",
            "Locates managed objects and reads their attributes from a KMIP key "
            "manager: algorithm, length, state and activation dates.",
            "Provide a KMIP endpoint and client certificate.",
            kmip_contract,
        ),
        (
            "cloud_kms",
            "cloud_kms",
            "Cloud KMS",
            "declared",
            "cloud",
            "Reads key metadata and rotation status from AWS KMS, Azure Key Vault, "
            "GCP KMS or Vault Transit.",
            "Provide read-only cloud credentials for the target account.",
            cloud_kms_contract,
        ),
        (
            "keystore",
            "keystore",
            "Keystore / X.509",
            "artifact_parsed",
            "host",
            "Parses keytool -list -v stores and X.509 chain metadata. Proves "
            "certificate parameters on disk; does not prove the running process "
            "loaded the store.",
            "Provide a keystore path or certificate export to parse.",
            keystore_contract,
        ),
    ):
        plugin_id, adapter_id, name, provenance, zone, description, requirement, contract_fn = spec
        registry.register(
            FunctionPlugin(
                id=plugin_id,
                name=name,
                provenance=provenance,
                zone=zone,
                description=description,
                fn=lambda **kw: [],
                availability=_live_blind_spot(adapter_id, requirement),
                requires_configuration=True,
                coverage_contract=contract_fn(),
                measurement=_adapter_measurement(adapter_id),
            )
        )

    registry.register(
        FunctionPlugin(
            id="runtime_trace",
            name="Runtime crypto tracing",
            provenance="runtime_observed",
            zone="host",
            description=(
                "Traces cryptographic operations as they execute, distinguishing "
                "cryptography that is live from cryptography that merely exists."
            ),
            fn=lambda **kw: [],
            availability=_unconfigured(
                "Requires a host agent with kernel tracing privileges."
            ),
            requires_configuration=True,
        )
    )

    return registry


def surface() -> dict:
    """Everything the discovery page needs: sensors, adapters, coverage and gaps."""
    registry = register_builtins()
    adapters = describe_adapters()
    return {
        "plugins": registry.describe_all(),
        "adapters": adapters,
        "coverage": registry.coverage(),
    }
