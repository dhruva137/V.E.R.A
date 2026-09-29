"""Cloud KMS and certificate-service adapter (AWS / Azure / GCP).

Keys: DescribeKey / key attributes / CryptoKeyVersion. Certificates: ACM DescribeCertificate, Key Vault certificate
bundles, Certificate Manager certificates. Read-only describe calls only, never export paths.
"""

from __future__ import annotations

from typing import Any

from models.schemas import RawCryptoFinding

ADAPTER_ID = "cloud_kms"


def parse(doc: dict) -> list[RawCryptoFinding]:
    from collectors.vault_collector import _from_cloud
    return _from_cloud(doc)


def coverage_contract() -> dict[str, Any]:
    return {
        "adapter_id": ADAPTER_ID,
        "proves": [
            "key spec / algorithm",
            "usage / key ops",
            "rotation and state attributes when present",
            "protection level / origin when the cloud API reports it",
            "certificate key algorithm, size, validity and (ACM) what uses it",
        ],
        "cannot_prove": [
            "managed key bytes (never exported)",
            "which workloads still call the key",
        ],
        "requires": [
            "AWS DescribeKey / Azure key attrs / GCP CryptoKeyVersion dump",
            "optionally ACM DescribeCertificate / Key Vault certificates / Certificate Manager certificates",
        ],
    }


class CloudKmsAdapter:
    id = ADAPTER_ID
    name = "Cloud KMS DescribeKey"

    def parse(self, doc: dict) -> list[RawCryptoFinding]:
        return parse(doc)

    def coverage_contract(self) -> dict[str, Any]:
        return coverage_contract()
