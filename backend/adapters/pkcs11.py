"""PKCS#11 HSM attribute adapter.

Reads C_FindObjects / C_GetAttributeValue shaped dumps. Never opens a
read-write session and never requests CKA_VALUE — scrub still drops it if a
careless export included it.
"""

from __future__ import annotations

from typing import Any

from models.schemas import RawCryptoFinding

ADAPTER_ID = "pkcs11"


def parse(doc: dict) -> list[RawCryptoFinding]:
    """Delegate to the vault collector parser — same demo and live path."""
    from collectors.vault_collector import _from_pkcs11
    return _from_pkcs11(doc)


def coverage_contract() -> dict[str, Any]:
    return {
        "adapter_id": ADAPTER_ID,
        "proves": [
            "key type and size",
            "label / CKA_ID",
            "usage flags (sign/encrypt)",
            "token firmware PQC mechanism readiness",
            "extractable / sensitive attributes when present",
        ],
        "cannot_prove": [
            "private key material",
            "runtime liveness of the wrapping application",
            "TR-31 key class without label convention",
        ],
        "requires": [
            "PKCS#11 attribute dump or read-only session",
            "slot / token metadata including mechanism list when available",
        ],
    }


class Pkcs11Adapter:
    id = ADAPTER_ID
    name = "PKCS#11 HSM attributes"

    def parse(self, doc: dict) -> list[RawCryptoFinding]:
        return parse(doc)

    def coverage_contract(self) -> dict[str, Any]:
        return coverage_contract()
