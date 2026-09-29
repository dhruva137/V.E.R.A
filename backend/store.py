"""SQLite persistence for scan runs.

The blueprint locks SQLite as storage; the previous version kept everything in
module-level globals, so a reload lost the demo and scan-to-scan comparison was
impossible. Comparison is exactly what the hybrid harness needs: migrate,
rescan, show the score drop against the recorded baseline.

One row per scan run, holding the scored assets, the CBOM and the summary. At
this scale (a few hundred assets per run) storing the payload as JSON is the
right trade - a normalised schema would buy nothing and cost migration
headaches during a build week.
"""

from __future__ import annotations

import datetime
import json
import os
import sqlite3
import threading
from pathlib import Path

# Overridable so a deployment can point this at a mounted volume. Without a
# volume the database lives in the container filesystem and is lost on
# redeploy, which is acceptable - a scan takes milliseconds to re-run - but it
# does mean scan history does not survive a restart.
DB_PATH = Path(
    os.environ.get("VERA_DB_PATH", Path(__file__).parent / "data" / "vera.db")
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id             TEXT PRIMARY KEY,
    timestamp           TEXT NOT NULL,
    kind                TEXT NOT NULL,
    label               TEXT NOT NULL,
    org_persona         TEXT NOT NULL,
    total_assets        INTEGER NOT NULL,
    quantum_vulnerable  INTEGER NOT NULL,
    classically_broken  INTEGER NOT NULL,
    negative_slack      INTEGER NOT NULL,
    avg_qirs            REAL NOT NULL,
    cbom_valid          INTEGER NOT NULL,
    assets_json         TEXT NOT NULL,
    cbom_json           TEXT NOT NULL,
    summary_json        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans (timestamp DESC);
"""

# SQLite connections are not safe to share across threads by default, and
# FastAPI serves sync endpoints from a thread pool. A lock plus
# check_same_thread=False is the simple correct answer at this scale.
_lock = threading.Lock()
_connection: sqlite3.Connection | None = None


def _connect() -> sqlite3.Connection:
    global _connection
    if _connection is None:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        _connection = sqlite3.connect(DB_PATH, check_same_thread=False)
        _connection.row_factory = sqlite3.Row
        _connection.executescript(_SCHEMA)
        _connection.commit()
    return _connection


def init() -> None:
    with _lock:
        _connect()


def save_scan(
    scan_id: str,
    kind: str,
    label: str,
    org_persona: str,
    assets: list,
    cbom: dict,
    summary: dict,
    cbom_valid: bool,
) -> None:
    payload = [a.model_dump() for a in assets]
    vulnerable = sum(1 for a in assets if a.quantum_vulnerable)
    broken = sum(1 for a in assets if a.classically_broken)
    # The dashboard's own count (recommendations.behind: needs a change and cannot
    # finish it in time), so the history and the Overview never disagree.
    behind = int(summary.get("negative_slack_count", 0))
    avg_qirs = round(sum(a.qirs for a in assets) / len(assets), 6) if assets else 0.0

    with _lock:
        connection = _connect()
        connection.execute(
            """
            INSERT OR REPLACE INTO scans (
                scan_id, timestamp, kind, label, org_persona, total_assets,
                quantum_vulnerable, classically_broken, negative_slack, avg_qirs,
                cbom_valid, assets_json, cbom_json, summary_json
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                scan_id,
                datetime.datetime.now(datetime.timezone.utc).isoformat(),
                kind,
                label,
                org_persona,
                len(assets),
                vulnerable,
                broken,
                behind,
                avg_qirs,
                int(cbom_valid),
                json.dumps(payload),
                json.dumps(cbom),
                json.dumps(summary),
            ),
        )
        connection.commit()


def list_scans(limit: int = 25) -> list[dict]:
    with _lock:
        rows = _connect().execute(
            """
            SELECT scan_id, timestamp, kind, label, total_assets,
                   quantum_vulnerable, avg_qirs, negative_slack
            FROM scans ORDER BY timestamp DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [
        {
            "scan_id": row["scan_id"],
            "timestamp": row["timestamp"],
            "kind": row["kind"],
            "label": row["label"],
            "total_assets": row["total_assets"],
            "quantum_vulnerable": row["quantum_vulnerable"],
            "avg_qirs": row["avg_qirs"],
            "negative_slack_count": row["negative_slack"],
        }
        for row in rows
    ]


def get_scan(scan_id: str) -> dict | None:
    with _lock:
        row = _connect().execute(
            "SELECT * FROM scans WHERE scan_id = ?", (scan_id,)
        ).fetchone()
    if row is None:
        return None
    return {
        "scan_id": row["scan_id"],
        "timestamp": row["timestamp"],
        "kind": row["kind"],
        "label": row["label"],
        "org_persona": row["org_persona"],
        "cbom_valid": bool(row["cbom_valid"]),
        "assets": json.loads(row["assets_json"]),
        "cbom": json.loads(row["cbom_json"]),
        "summary": json.loads(row["summary_json"]),
    }


def asset_history(asset_id: str, label: str, limit: int = 10) -> list[dict]:
    """How one asset looked in the most recent scans of the same estate (same label), newest first."""
    with _lock:
        rows = _connect().execute(
            """
            SELECT s.scan_id, s.timestamp, j.value AS asset
            FROM scans s, json_each(s.assets_json) j
            WHERE s.label = ? AND json_extract(j.value, '$.id') = ?
            ORDER BY s.timestamp DESC LIMIT ?
            """,
            (label, asset_id, limit),
        ).fetchall()
    out = []
    for row in rows:
        asset = json.loads(row["asset"])
        out.append({"scan_id": row["scan_id"], "timestamp": row["timestamp"],
                    **{k: asset.get(k) for k in ("algorithm", "key_size", "verdict", "risk_level", "mosca_category",
                                                 "slack_months", "priority_rank", "migrated")}})
    return out


def latest_scan() -> dict | None:
    with _lock:
        row = _connect().execute(
            "SELECT scan_id FROM scans ORDER BY timestamp DESC LIMIT 1"
        ).fetchone()
    return get_scan(row["scan_id"]) if row else None
