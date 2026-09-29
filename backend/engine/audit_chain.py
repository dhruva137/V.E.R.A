"""Tamper-evident audit log: a hash chain in an append-only SQLite table.

Every scan, export, setting change, agent action and sign-in appends one entry:

    entry_hash = SHA-256( canonical_json(entry without entry_hash) + prev_hash )

where `prev_hash` is the previous entry's hash (64 zeros for the first). Change
any stored field, delete a row or reorder rows and every later hash stops
matching, so `verify()` reports the first index where the chain breaks.

Two layers, deliberately:
  - SQLite triggers refuse UPDATE and DELETE on the table, so the application
    itself cannot rewrite history by accident.
  - The chain catches anyone who bypasses the application: dropping the
    triggers and editing a row with raw SQL still breaks verification at that
    row. The test suite does exactly that.

Entries record *what happened* (kind, action, a small detail object), never
key material or scan payloads; details pass through the same scrub as findings.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import sqlite3
import threading
from pathlib import Path

from engine.intake.scrub import scrub

GENESIS = "0" * 64
KINDS = ("scan", "export", "setting", "agent", "auth", "system")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_chain (
    idx        INTEGER PRIMARY KEY,
    at         TEXT NOT NULL,
    kind       TEXT NOT NULL,
    action     TEXT NOT NULL,
    actor      TEXT NOT NULL,
    detail     TEXT NOT NULL,
    prev_hash  TEXT NOT NULL,
    entry_hash TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS audit_chain_no_update BEFORE UPDATE ON audit_chain
BEGIN SELECT RAISE(ABORT, 'audit_chain is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_chain_no_delete BEFORE DELETE ON audit_chain
BEGIN SELECT RAISE(ABORT, 'audit_chain is append-only'); END;
"""


def _canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def entry_hash(entry: dict, prev_hash: str) -> str:
    body = {k: v for k, v in entry.items() if k != "entry_hash"}
    return hashlib.sha256((_canonical(body) + prev_hash).encode("utf-8")).hexdigest()


def _detail(raw) -> dict:
    """A stored detail, decoded. An undecodable one is evidence of tampering, so it is kept and marked."""
    try:
        return {"detail": json.loads(raw)}
    except (TypeError, ValueError):
        return {"detail": {"unreadable": str(raw)[:200]}, "malformed": True}


class AuditChain:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(self.path, check_same_thread=False)
        self._db.executescript(_SCHEMA)
        self._db.commit()

    def append(self, kind: str, action: str, detail: dict | None = None, actor: str = "system") -> dict:
        if kind not in KINDS:
            raise ValueError(f"audit kind must be one of {KINDS}, got {kind!r}")
        with self._lock:
            row = self._db.execute("SELECT idx, entry_hash FROM audit_chain ORDER BY idx DESC LIMIT 1").fetchone()
            idx, prev = (row[0] + 1, row[1]) if row else (0, GENESIS)
            entry = {
                "idx": idx,
                "at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
                "kind": kind,
                "action": action,
                "actor": actor,
                "detail": scrub(dict(detail or {})),
                "prev_hash": prev,
            }
            entry["entry_hash"] = entry_hash(entry, prev)
            self._db.execute(
                "INSERT INTO audit_chain (idx, at, kind, action, actor, detail, prev_hash, entry_hash) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (idx, entry["at"], kind, action, actor, _canonical(entry["detail"]), prev, entry["entry_hash"]))
            self._db.commit()
            return entry

    def entries(self, limit: int | None = None) -> list[dict]:
        """Every entry in order. Read under the append lock: one connection is shared across request threads."""
        query = "SELECT idx, at, kind, action, actor, detail, prev_hash, entry_hash FROM audit_chain ORDER BY idx"
        with self._lock:
            rows = self._db.execute(query).fetchall()
        out = [{"idx": r[0], "at": r[1], "kind": r[2], "action": r[3], "actor": r[4], **_detail(r[5]),
                "prev_hash": r[6], "entry_hash": r[7]} for r in rows]
        return out[-limit:] if limit else out

    def verify(self) -> dict:
        """Walk the chain. `first_broken` is the index of the first entry that does not verify."""
        prev = GENESIS
        entries = self.entries()
        for position, entry in enumerate(entries):
            reason = None
            if entry.get("malformed"):
                reason = "detail is not valid JSON (the row was edited outside the application)"
            elif entry["idx"] != position:
                reason = f"index {entry['idx']} found at position {position} (a row was deleted or reordered)"
            elif entry["prev_hash"] != prev:
                reason = "prev_hash does not match the previous entry's hash"
            elif entry_hash(entry, prev) != entry["entry_hash"]:
                reason = "entry_hash does not match the entry's contents"
            if reason:
                return {"valid": False, "entries": len(entries), "first_broken": position, "reason": reason}
            prev = entry["entry_hash"]
        return {"valid": True, "entries": len(entries), "first_broken": None, "head": prev}


_default: AuditChain | None = None
_default_lock = threading.Lock()


def default() -> AuditChain:
    """The process-wide chain, next to the scan store (`VERA_AUDIT_DB` overrides)."""
    global _default
    with _default_lock:
        if _default is None:
            from store import DB_PATH

            _default = AuditChain(os.environ.get("VERA_AUDIT_DB") or Path(DB_PATH).with_name("audit_chain.db"))
        return _default


def append(kind: str, action: str, detail: dict | None = None, actor: str = "system") -> dict:
    """Append to the process chain. A generic actor becomes the signed-in user when there is one."""
    if actor in ("system", "operator"):
        from engine.auth import CURRENT_USER

        user = CURRENT_USER.get()
        if user:
            actor = f"user:{user['username']}"
    return default().append(kind, action, detail, actor)
