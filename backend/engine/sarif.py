"""SARIF 2.1.0 export, so a CI pipeline can gate a merge on quantum risk.

One SARIF rule per finding class (the recommendation need: Shor-exposed key
exchange, high-volume signature, classically broken, library below its PQC
release, key baked into an artefact, ...) plus one rule per drift rule. Levels:

    critical / high risk, classically broken, secret exposure  ->  error
    medium                                                    ->  warning
    low / minimal / informational                             ->  note

Locations: source and config findings get a file URI with the start line;
binaries and container findings get the artefact path (and the path inside
the image); live endpoints get a `tls://` or `ssh://` URI. Each result carries
a stable `partialFingerprints` entry so a CI system can track it across runs.

The output is validated against the vendored OASIS SARIF 2.1.0 schema
(`engine.schema_validation`). Output is deterministic for a given scan.
"""

from __future__ import annotations

import re
from pathlib import PureWindowsPath

from engine import recommendations as rec
from engine.version import TOOL_NAME, TOOL_VERSION

SCHEMA_URI = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
_LEVEL_BY_RISK = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "minimal": "note",
                  "informational": "note", "safe": "note"}
_ALWAYS_ERROR = {"replace_now", "secret_exposure"}


def _rule_id(need: str) -> str:
    return "VERA-" + need.upper().replace("_", "-")


def _uri(location: str, endpoint_scheme: str | None = None) -> tuple[str, int | None]:
    """(artifact URI, start line) for a finding's source_location.

    `endpoint_scheme` ("tls" / "ssh") marks a live endpoint, whose "host:port"
    must not be read as "file:line".
    """
    if endpoint_scheme and not re.match(r"^[a-z]+://", location or ""):
        return f"{endpoint_scheme}://{location}", None
    line = None
    m = re.match(r"^(.*?):(\d+)$", location or "")
    if m and not re.match(r"^[a-z]+://[^/]+:\d+$", location):
        location, line = m.group(1), int(m.group(2))
    if re.match(r"^[a-z][a-z0-9+.-]*://", location or "", re.I):
        return location, line
    if "!/" in location:                                   # path inside a container image or archive
        image, inner = location.split("!/", 1)
        is_path = re.match(r"^[A-Za-z]:[\\/]|^/", image)
        return (f"{_file_uri(image)}#/{inner}" if is_path else f"{image}#/{inner}"), line
    return _file_uri(location), line


def _file_uri(path: str) -> str:
    if re.match(r"^[A-Za-z]:[\\/]", path):
        return PureWindowsPath(path).as_uri()
    if path.startswith("/"):
        return "file://" + path
    return path.replace("\\", "/")


def generate_sarif(assets, drift_records: list[dict] | None = None, profile: str | None = None) -> dict:
    profile = profile or rec.active_profile()
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for asset in sorted(assets, key=lambda a: (a.priority_rank or 10**9, a.id)):
        item = rec.recommend(asset, profile)
        if item is None:
            continue
        rule_id = _rule_id(item["need"])
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": item["need"].replace("_", " ").title().replace(" ", ""),
            "shortDescription": {"text": item["need_label"]},
            "fullDescription": {"text": item["rationale"]},
            "help": {"text": f"Recommended ({profile}): {item['recommended']}. " + item["rationale"]},
            "properties": {"tags": ["cryptography", "post-quantum"] +
                           (["classically-broken"] if item["need"] == "replace_now" else [])},
        })
        level = "error" if item["need"] in _ALWAYS_ERROR else _LEVEL_BY_RISK.get(asset.risk_level, "warning")
        uri, line = _uri(asset.source_location, asset.source_type if asset.source_type in ("tls", "ssh") else None)
        physical: dict = {"artifactLocation": {"uri": uri}}
        if line:
            physical["region"] = {"startLine": line}
        details = asset.raw_details or {}
        results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {"text": f"{asset.name}: {item['why']} Recommended: {item['recommended']}."},
            "locations": [{"physicalLocation": physical}],
            "partialFingerprints": {"veraAssetId/v1": asset.id},
            "properties": {
                "algorithm": item["algorithm"], "qirs": round(asset.qirs, 6), "risk": asset.risk_level,
                "moscaCategory": asset.mosca_category or "not_applicable", "priorityRank": asset.priority_rank,
                "system": details.get("system"), "pathInImage": details.get("path_in_image"),
            },
        })

    for record in drift_records or []:
        rule_id = "VERA-DRIFT-" + record["rule"]
        rules.setdefault(rule_id, {
            "id": rule_id, "name": f"Drift{record['rule']}",
            "shortDescription": {"text": record["title"]},
            "fullDescription": {"text": "Declared and observed evidence disagree."},
            "properties": {"tags": ["cryptography", "drift"]},
        })
        observed = record["observed"]
        scheme = None
        if observed.get("plane") == "observed":
            scheme = next((k for k in ("ssh", "tls") if k in str(observed.get("collector", ""))), None)
        uri, line = _uri(observed.get("location") or record["declared"].get("location") or "", scheme)
        physical = {"artifactLocation": {"uri": uri or "about:blank"}}
        if line:
            physical["region"] = {"startLine": line}
        results.append({
            "ruleId": rule_id,
            "level": "error" if record["severity"] in ("critical", "high") else "warning",
            "message": {"text": record["explain"]},
            "locations": [{"physicalLocation": physical}],
            "partialFingerprints": {"veraDriftId/v1": record["id"]},
            "properties": {"severity": record["severity"], "declared": record["declared"]["value"],
                           "observed": record["observed"]["value"]},
        })

    return {
        "$schema": SCHEMA_URI,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": TOOL_NAME, "version": TOOL_VERSION,
                                "rules": [rules[k] for k in sorted(rules)]}},
            "results": results,
            "properties": {"profile": profile},
        }],
    }
