"""TLS handshake adapter.

Completed handshake findings only — the sole runtime_observed inlet among the
first five adapters.
"""

from __future__ import annotations

from typing import Any

from models.schemas import RawCryptoFinding

ADAPTER_ID = "tls"


def parse(doc: dict) -> list[RawCryptoFinding]:
    from collectors.vault_collector import _from_tls
    return _from_tls(doc)


def coverage_contract() -> dict[str, Any]:
    return {
        "adapter_id": ADAPTER_ID,
        "proves": [
            "certificate presented on the wire",
            "key-exchange group",
            "cipher suite",
        ],
        "cannot_prove": [
            "where the private key is custodied",
            "HSM / KMS binding of the leaf key",
        ],
        "requires": [
            "Completed TLS handshake record (findings[] document)",
        ],
    }


class TlsAdapter:
    id = ADAPTER_ID
    name = "TLS handshake"

    def parse(self, doc: dict) -> list[RawCryptoFinding]:
        return parse(doc)

    def coverage_contract(self) -> dict[str, Any]:
        return coverage_contract()
