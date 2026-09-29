"""Access keys for the external integration surface.

WHY THIS EXISTS
---------------
`/api/*` is the dashboard's own backend and is unauthenticated by design - the
demo states plainly that it authenticates nothing. `/api/v1/*` is different: it
lets *another* system call VERA's tools, including the one that changes the
estate. Handing that out unauthenticated would be handing out a write path.

WHAT IS AND IS NOT PROMISED
---------------------------
Keys live in memory and die with the process, exactly like the language-model
key. That is honest for a demo and wrong for production, which needs a real
store, per-key rate limits and revocation that survives a restart. The status
endpoint says so rather than implying otherwise.

Only a SHA-256 digest of each key is retained. The plaintext is returned once,
at creation, and cannot be recovered afterwards - so a leaked process memory
dump or an over-sharing status endpoint cannot leak a usable credential.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

PREFIX = "vera_sk_"
# Long enough that guessing is not the attack anyone would choose, short enough
# to paste into a config file without wrapping.
_ENTROPY_BYTES = 24


def _digest(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclass
class APIKey:
    """A key record. Never holds the plaintext."""

    id: str
    name: str
    digest: str
    hint: str                      # last four characters, to tell keys apart
    created_at: str
    scopes: list[str] = field(default_factory=lambda: ["read"])
    last_used_at: Optional[str] = None
    call_count: int = 0
    revoked: bool = False

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "hint": f"…{self.hint}",
            "created_at": self.created_at,
            "scopes": list(self.scopes),
            "last_used_at": self.last_used_at,
            "call_count": self.call_count,
            "revoked": self.revoked,
        }


class KeyStore:
    def __init__(self) -> None:
        self._keys: dict[str, APIKey] = {}

    def issue(self, name: str, scopes: Optional[list[str]] = None) -> tuple[APIKey, str]:
        """Create a key. Returns the record and the plaintext, once."""
        raw = PREFIX + secrets.token_urlsafe(_ENTROPY_BYTES)
        record = APIKey(
            id=secrets.token_hex(8),
            name=(name or "unnamed").strip()[:60],
            digest=_digest(raw),
            hint=raw[-4:],
            created_at=datetime.now(timezone.utc).isoformat(),
            # "write" is opt-in. A key that can only read cannot migrate an
            # asset even if the agent control plane would otherwise allow it.
            scopes=scopes or ["read"],
        )
        self._keys[record.id] = record
        return record, raw

    def verify(self, raw: Optional[str]) -> Optional[APIKey]:
        """Resolve a presented key, or None.

        Compared with `hmac.compare_digest` so the time taken does not depend on
        how many leading characters happened to match.
        """
        if not raw:
            return None
        candidate = _digest(raw.strip())
        for record in self._keys.values():
            if record.revoked:
                continue
            if hmac.compare_digest(record.digest, candidate):
                record.last_used_at = datetime.now(timezone.utc).isoformat()
                record.call_count += 1
                return record
        return None

    def revoke(self, key_id: str) -> bool:
        record = self._keys.get(key_id)
        if not record or record.revoked:
            return False
        record.revoked = True
        return True

    def delete(self, key_id: str) -> bool:
        return self._keys.pop(key_id, None) is not None

    def list(self) -> list[dict]:
        return [k.to_dict() for k in sorted(
            self._keys.values(), key=lambda k: k.created_at, reverse=True,
        )]

    def active_count(self) -> int:
        return sum(1 for k in self._keys.values() if not k.revoked)


_store = KeyStore()


def get_store() -> KeyStore:
    return _store
