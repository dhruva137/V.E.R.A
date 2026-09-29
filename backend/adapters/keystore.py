"""Keystore / X.509 adapter.

keytool -list -v shaped stores and parsed certificate chains. Same certificate
seen in a JKS and in a chain file correlates upstream via identity_key.
"""

from __future__ import annotations

from typing import Any

from models.schemas import RawCryptoFinding

ADAPTER_ID = "keystore"


def parse(doc: dict) -> list[RawCryptoFinding]:
    """Parse keystores.json or certificates.json shaped documents.

    Dispatches on document shape so one adapter covers both vault sources that
    share the keystore/artifact provenance grade.
    """
    from collectors.vault_collector import _from_certificates, _from_keystores

    if "stores" in doc:
        return _from_keystores(doc)
    if "certificates" in doc:
        return _from_certificates(doc)
    return []


def coverage_contract() -> dict[str, Any]:
    return {
        "adapter_id": ADAPTER_ID,
        "proves": [
            "certificate subject / issuer / serial",
            "public key algorithm and size",
            "validity window",
            "keystore path + alias when from a store listing",
        ],
        "cannot_prove": [
            "private key bytes (parsing stops at the certificate)",
            "whether the key is also held in an HSM",
        ],
        "requires": [
            "keytool -list -v export and/or parsed X.509 metadata",
        ],
    }


class KeystoreAdapter:
    id = ADAPTER_ID
    name = "Keystore / X.509"

    def parse(self, doc: dict) -> list[RawCryptoFinding]:
        return parse(doc)

    def coverage_contract(self) -> dict[str, Any]:
        return coverage_contract()
