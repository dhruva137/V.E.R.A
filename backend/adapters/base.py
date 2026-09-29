"""Adapter protocol — read-only, metadata-only, never key material.

WHY THIS EXISTS
---------------
Every inlet (PKCS#11 dump, KMIP GetAttributes, cloud KMS DescribeKey, TLS
handshake, keystore list) must speak one contract. The protocol is the seam:
parse a native document into findings, declare what the sensor can and cannot
prove. Coverage gaps are inventory facts, not missing features.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from models.schemas import RawCryptoFinding


@runtime_checkable
class Adapter(Protocol):
    """One native source shape → findings, with an explicit coverage contract."""

    id: str
    name: str

    def parse(self, doc: dict) -> list[RawCryptoFinding]:
        """Parse a native (already-loaded) document into findings."""
        ...

    def coverage_contract(self) -> dict[str, Any]:
        """What this adapter can prove, cannot prove, and requires to run."""
        ...
