"""Projects: a named piece of assessment work, with its targets, its scans and its assistant conversations.

An NTRO analyst characterising one vendor's appliance, a CISO's Milestone-1 inventory and an auditor's CERT-In
check are different jobs over different targets. A project keeps each job's targets, the scans run for it and
the assistant conversations held about it together, so work can be resumed and handed over.

Stored in the same SQLite file as the scans (store.py), under the same lock. Conversations are kept as the
messages exchanged, nothing else; they never contain key material because the engine never holds any.
"""

from __future__ import annotations

import datetime
import json
import uuid

import store

_SCHEMA = """
CREATE TABLE IF NOT EXISTS projects (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    purpose      TEXT NOT NULL,
    sector       TEXT NOT NULL,
    targets_json TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    created_by   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS project_scans (
    project_id TEXT NOT NULL,
    scan_id    TEXT NOT NULL,
    added_at   TEXT NOT NULL,
    PRIMARY KEY (project_id, scan_id)
);
CREATE TABLE IF NOT EXISTS threads (
    id            TEXT PRIMARY KEY,
    project_id    TEXT,
    title         TEXT NOT NULL,
    messages_json TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    created_by    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_threads_project ON threads (project_id, updated_at DESC);
"""
_ready = False


def _db():
    global _ready
    db = store._connect()
    if not _ready:
        db.executescript(_SCHEMA)
        db.commit()
        _ready = True
    return db


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def _project(row) -> dict:
    return {"id": row["id"], "name": row["name"], "purpose": row["purpose"], "sector": row["sector"],
            "targets": json.loads(row["targets_json"]), "created_at": row["created_at"], "created_by": row["created_by"]}


def create(name: str, purpose: str, sector: str, targets: list[dict], by: str) -> dict:
    if not name.strip():
        raise ValueError("A project needs a name.")
    pid = uuid.uuid4().hex[:12]
    with store._lock:
        db = _db()
        db.execute("INSERT INTO projects VALUES (?, ?, ?, ?, ?, ?, ?)",
                   (pid, name.strip(), purpose.strip(), sector, json.dumps(targets), _now(), by))
        db.commit()
    return get(pid)


def get(pid: str) -> dict | None:
    with store._lock:
        row = _db().execute("SELECT * FROM projects WHERE id = ?", (pid,)).fetchone()
    return _project(row) if row else None


def update(pid: str, **fields) -> dict | None:
    allowed = {"name": "name", "purpose": "purpose", "sector": "sector", "targets": "targets_json"}
    sets = [(allowed[k], json.dumps(v) if k == "targets" else v) for k, v in fields.items() if k in allowed and v is not None]
    if sets:
        with store._lock:
            db = _db()
            db.execute(f"UPDATE projects SET {', '.join(f'{c} = ?' for c, _ in sets)} WHERE id = ?",
                       [v for _, v in sets] + [pid])
            db.commit()
    return get(pid)


def delete(pid: str) -> bool:
    with store._lock:
        db = _db()
        n = db.execute("DELETE FROM projects WHERE id = ?", (pid,)).rowcount
        db.execute("DELETE FROM project_scans WHERE project_id = ?", (pid,))
        db.execute("UPDATE threads SET project_id = NULL WHERE project_id = ?", (pid,))
        db.commit()
    return bool(n)


def link_scan(pid: str, scan_id: str) -> None:
    with store._lock:
        db = _db()
        db.execute("INSERT OR IGNORE INTO project_scans VALUES (?, ?, ?)", (pid, scan_id, _now()))
        db.commit()


def scans(pid: str) -> list[dict]:
    """The project's scans, newest first, with the headline numbers each one recorded."""
    with store._lock:
        rows = _db().execute(
            "SELECT s.scan_id, s.timestamp, s.label, s.total_assets, s.quantum_vulnerable, s.negative_slack "
            "FROM project_scans p JOIN scans s ON s.scan_id = p.scan_id WHERE p.project_id = ? "
            "ORDER BY s.timestamp DESC", (pid,)).fetchall()
    return [{"scan_id": r[0], "timestamp": r[1], "label": r[2], "assets": r[3], "quantum_vulnerable": r[4],
             "late_for_dst": r[5]} for r in rows]


def list_all() -> list[dict]:
    with store._lock:
        rows = _db().execute("SELECT * FROM projects ORDER BY created_at DESC").fetchall()
        counts = dict(_db().execute("SELECT project_id, COUNT(*) FROM project_scans GROUP BY project_id").fetchall())
        threads_n = dict(_db().execute("SELECT project_id, COUNT(*) FROM threads GROUP BY project_id").fetchall())
    return [{**_project(r), "scans": counts.get(r["id"], 0), "conversations": threads_n.get(r["id"], 0)} for r in rows]


# ------------------------------------------------------------------ assistant conversations

def _thread(row, with_messages: bool) -> dict:
    out = {"id": row["id"], "project_id": row["project_id"], "title": row["title"], "created_at": row["created_at"],
           "updated_at": row["updated_at"], "created_by": row["created_by"]}
    msgs = json.loads(row["messages_json"])
    out["messages" if with_messages else "message_count"] = msgs if with_messages else len(msgs)
    return out


def threads(project_id: str | None) -> list[dict]:
    with store._lock:
        rows = _db().execute(
            "SELECT * FROM threads WHERE project_id IS ? ORDER BY updated_at DESC", (project_id,)).fetchall()
    return [_thread(r, False) for r in rows]


def get_thread(tid: str) -> dict | None:
    with store._lock:
        row = _db().execute("SELECT * FROM threads WHERE id = ?", (tid,)).fetchone()
    return _thread(row, True) if row else None


def save_thread(tid: str | None, project_id: str | None, messages: list[dict], by: str, title: str = "") -> dict:
    """Create or replace a conversation. The title defaults to the first question asked."""
    kept = [{"role": m["role"], "content": str(m.get("content", ""))} for m in messages
            if m.get("role") in ("user", "assistant")]
    first = next((m["content"] for m in kept if m["role"] == "user"), "New conversation")
    title = (title or first).strip()[:80] or "New conversation"
    now = _now()
    with store._lock:
        db = _db()
        if tid and db.execute("SELECT 1 FROM threads WHERE id = ?", (tid,)).fetchone():
            db.execute("UPDATE threads SET messages_json = ?, title = ?, updated_at = ? WHERE id = ?",
                       (json.dumps(kept), title, now, tid))
        else:
            tid = uuid.uuid4().hex[:12]
            db.execute("INSERT INTO threads VALUES (?, ?, ?, ?, ?, ?, ?)",
                       (tid, project_id, title, json.dumps(kept), now, now, by))
        db.commit()
    return get_thread(tid)


def delete_thread(tid: str) -> bool:
    with store._lock:
        db = _db()
        n = db.execute("DELETE FROM threads WHERE id = ?", (tid,)).rowcount
        db.commit()
    return bool(n)
