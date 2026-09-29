"""Estate register: the organisation's own declaration of its systems.

The PS asks for artefacts "across internal and external facing applications,
products and infrastructure" and classified "by type, lifetime and business
criticality". None of those are properties a scanner can read off a file: an
organisation declares them. The register is that declaration, one entry per
system, and it drives the whole scan:

    name: Demo Payments
    systems:
      - name: payments-gateway
        exposure: internet            # internet | internal
        criticality: critical         # critical | high | medium | low
        data_classes: [payment_card, customer_pii]
        hosts: [pay.demo.example:443]
        repo: repo/payments-gateway
        images: [images/payments-gateway.oci.tar#base_layers=1]
        configs: [{path: configs/pay-gw, host: pay.demo.example:443}]
        captures: [captures/tls.json]
    vault: vault

Every finding from a system's targets is stamped with the system name, its
declared exposure, criticality and data classes, so the risk model (WP7) reads
data lifetime from the organisation's own classification, not a default. The
register itself becomes `system` declarations that drift rule D8 compares with
where endpoints actually answer.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

TARGET_KEYS = (("repo", "repo"), ("repos", "repo"), ("paths", "path"), ("configs", "path"),
               ("images", "image"), ("captures", "capture"), ("live_hosts", "host"))


@dataclass
class Target:
    kind: str                  # path | repo | image | capture | vault | host
    value: str
    system: str | None = None
    host: str | None = None
    exposure: str | None = None
    criticality: str | None = None
    data_classes: list[str] = field(default_factory=list)
    collectors: list[str] | None = None

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v not in (None, [], "")}


def _resolve(base: Path, value: str) -> str:
    """Relative paths resolve against the register's directory; options after '#' are kept."""
    path, sep, options = str(value).partition("#")
    if "://" in path or path.startswith("git@"):
        return value
    resolved = (base / path).resolve() if not Path(path).is_absolute() else Path(path)
    return f"{resolved}{sep}{options}"


def load(register: str | Path) -> tuple[list[Target], list[dict], dict]:
    """(targets, system declarations, register metadata) from a register file."""
    path = Path(register)
    doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    base = path.parent
    text = path.read_text(encoding="utf-8")
    targets: list[Target] = []
    declarations: list[dict] = []
    for system in doc.get("systems", []):
        name = system["name"]
        hosts = [str(h).lower() for h in system.get("hosts", [])]
        exposure = system.get("exposure")
        if exposure not in (None, "internet", "internal"):
            raise ValueError(f"{name}: exposure must be 'internet' or 'internal', got {exposure!r}")
        common = {"system": name, "exposure": exposure, "criticality": system.get("criticality"),
                  "data_classes": list(system.get("data_classes", []))}
        declarations.append({
            "kind": "system", "name": name, "hosts": hosts, "exposure": exposure,
            "criticality": system.get("criticality"), "data_classes": common["data_classes"],
            "owner": system.get("owner"), "source": "estate_register",
            "location": f"{path}:{text[: text.find('name: ' + name)].count(chr(10)) + 1}",
        })
        for key, kind in TARGET_KEYS:
            values = system.get(key)
            if values is None:
                continue
            for entry in values if isinstance(values, list) else [values]:
                if isinstance(entry, dict):
                    value, host = entry["path"], entry.get("host")
                else:
                    value, host = entry, None
                if kind == "path" and key == "configs" and host is None and hosts:
                    host = hosts[0]
                targets.append(Target(kind=kind, value=value if kind == "host" else _resolve(base, value),
                                      host=host, **common))
    # Estate-wide sources: recorded observations span many systems, and key
    # managers are shared; each finding is tied to a system later by its host.
    for value in doc.get("captures", []) or []:
        targets.append(Target(kind="capture", value=_resolve(base, value)))
    for value in ([doc["vault"]] if doc.get("vault") else []) + list(doc.get("vaults", []) or []):
        targets.append(Target(kind="vault", value=_resolve(base, value)))
    meta = {"name": doc.get("name", path.stem), "register": str(path), "systems": len(declarations),
            "synthetic": bool(doc.get("synthetic", False)), "cost": doc.get("cost") or {}}
    return targets, declarations, meta
