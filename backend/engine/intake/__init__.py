"""Intake plane — scrub, identity, and the sensor/object contract.

Adapters emit findings (today) and will emit SensorObservations; identity folds
duplicates; scrub refuses key material. The engine core must never import a
native file shape from here — only these types.
"""

from engine.intake.contract import (
    ClaimKind,
    CryptoObjectView,
    SensorObservation,
    stamp_finding_custody,
)
from engine.intake.identity import correlate_findings, identity_key
from engine.intake.scrub import FORBIDDEN, scrub

__all__ = [
    "ClaimKind",
    "CryptoObjectView",
    "FORBIDDEN",
    "SensorObservation",
    "correlate_findings",
    "identity_key",
    "scrub",
    "stamp_finding_custody",
]
