"""Metadata-only adapters — native shapes in, findings out.

Each adapter wraps a vault_collector parser so the demo path and the live path
share one parse. The engine may log adapter ids; it must not branch on them.

`describe_adapters` is the honest capability surface: coverage_contract plus
whether a file dump is present. It never invents live connectivity or asset
counts.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from adapters.base import Adapter
from adapters.cloud_kms import CloudKmsAdapter
from adapters.kmip import KmipAdapter
from adapters.keystore import KeystoreAdapter
from adapters.pkcs11 import Pkcs11Adapter
from adapters.tls import TlsAdapter
from collectors import vault_collector

__all__ = [
    "Adapter",
    "CloudKmsAdapter",
    "KmipAdapter",
    "KeystoreAdapter",
    "Pkcs11Adapter",
    "TlsAdapter",
    "ADAPTERS",
    "describe_adapters",
    "list_adapter_ids",
]

# Stable order — the first five inlets the product claims.
ADAPTERS: tuple[Adapter, ...] = (
    Pkcs11Adapter(),
    KmipAdapter(),
    CloudKmsAdapter(),
    TlsAdapter(),
    KeystoreAdapter(),
)

# Discovery plugin id (profiles / registry) keyed by adapter id.
PLUGIN_IDS: dict[str, str] = {
    "pkcs11": "hsm_pkcs11",
    "kmip": "kmip",
    "cloud_kms": "cloud_kms",
    "tls": "tls",
    "keystore": "keystore",
}

# Vault files that make each adapter measurable without live credentials.
_VAULT_FILES: dict[str, tuple[str, ...]] = {
    "pkcs11": ("hsm_pkcs11.json",),
    "kmip": ("kmip.json",),
    "cloud_kms": ("cloud_kms.json",),
    "tls": ("tls.json",),
    "keystore": ("keystores.json", "certificates.json"),
}

# What an operator must supply for a *live* read (not a file dump).
_LIVE_REQUIREMENTS: dict[str, str] = {
    "pkcs11": "Provide a PKCS#11 module path and a read-only slot credential.",
    "kmip": "Provide a KMIP endpoint and client certificate.",
    "cloud_kms": "Provide read-only cloud credentials for the target account.",
    "tls": "Provide TLS endpoints to probe (handshake targets).",
    "keystore": "Provide a keystore path or certificate export to parse.",
}


def list_adapter_ids() -> list[str]:
    return [a.id for a in ADAPTERS]


def _vault_root() -> Path:
    return vault_collector._resolve(None)


def _files_present(adapter_id: str, root: Path | None = None) -> tuple[list[str], list[str]]:
    directory = root or _vault_root()
    expected = list(_VAULT_FILES.get(adapter_id, ()))
    present = [name for name in expected if (directory / name).is_file()]
    return expected, present


def _measurement(adapter_id: str, root: Path | None = None) -> dict[str, Any]:
    """File-dump vs live — never fabricates Active asset counts."""
    expected, present = _files_present(adapter_id, root)
    live_reason = _LIVE_REQUIREMENTS.get(adapter_id, "Not configured for live collection.")
    if present:
        return {
            "mode": "file_dump",
            "label": "Measurable via file dump",
            "vault_files": expected,
            "vault_files_present": present,
            "live_configured": False,
            "live_reason": live_reason,
        }
    return {
        "mode": "unavailable",
        "label": "Not measured",
        "vault_files": expected,
        "vault_files_present": [],
        "live_configured": False,
        "live_reason": live_reason,
    }


def describe_adapters(vault_root: str | Path | None = None) -> list[dict[str, Any]]:
    """Capability cards for every registered adapter.

    Each card carries coverage_contract (proves / cannot_prove / requires) and
    an honest measurement status. No asset counts — those come only from a
    completed collect.
    """
    root = vault_collector._resolve(vault_root) if vault_root is not None else _vault_root()
    cards: list[dict[str, Any]] = []
    for adapter in ADAPTERS:
        contract = dict(adapter.coverage_contract())
        # Normalise keys the discovery surface and tests assert on.
        for key in ("proves", "cannot_prove", "requires"):
            contract.setdefault(key, [])
        contract.setdefault("adapter_id", adapter.id)
        cards.append(
            {
                "id": adapter.id,
                "name": adapter.name,
                "plugin_id": PLUGIN_IDS.get(adapter.id, adapter.id),
                "coverage_contract": contract,
                "measurement": _measurement(adapter.id, root),
            }
        )
    return cards
