"""KMIP GetAttributes adapter.

Locate + GetAttributes only — never Get, which can return key material.
"""

from __future__ import annotations

from typing import Any

from models.schemas import RawCryptoFinding

ADAPTER_ID = "kmip"


def parse(doc: dict) -> list[RawCryptoFinding]:
    from collectors.vault_collector import _from_kmip
    return _from_kmip(doc)


def coverage_contract() -> dict[str, Any]:
    return {
        "adapter_id": ADAPTER_ID,
        "proves": [
            "cryptographic algorithm and length",
            "usage mask",
            "lifecycle State",
            "unique identifier / name",
        ],
        "cannot_prove": [
            "key bytes (Get is refused)",
            "whether a Deactivated key still unwraps archived data in practice",
        ],
        "requires": [
            "KMIP Locate + GetAttributes response dump or endpoint",
        ],
    }


class KmipAdapter:
    id = ADAPTER_ID
    name = "KMIP GetAttributes"

    def parse(self, doc: dict) -> list[RawCryptoFinding]:
        return parse(doc)

    def coverage_contract(self) -> dict[str, Any]:
        return coverage_contract()
