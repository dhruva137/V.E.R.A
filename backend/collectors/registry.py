"""Every collector behind one contract (see `collectors.base`).

The function-style scanners that predate the contract (`scan_configs`,
`scan_source`, ...) are wrapped rather than rewritten, so their behaviour and
tests stay as they were. New collectors implement the contract directly and
register here. `/api/scan/full` and the Scan screen read this registry, so
a new collector appears in both with no other change.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from collectors.base import DEFAULT_LIMITS, CollectResult, Collector, Limits, Timer


class _FunctionCollector:
    """Adapts a `scan(paths) -> (findings, failures)` function to the contract."""

    def __init__(self, name: str, plane: str, label: str, description: str,
                 target_kinds: tuple[str, ...], scan: Callable, failure_key: str = "path"):
        self.name = name
        self.plane = plane
        self.label = label
        self.description = description
        self.target_kinds = target_kinds
        self._scan = scan
        self._failure_key = failure_key

    def collect(self, targets: list[str], *, limits: Limits = DEFAULT_LIMITS) -> CollectResult:
        timer = Timer(limits)
        result = CollectResult(stats={"targets": len(targets)})
        if not targets:
            return result
        findings, failures = self._scan(list(targets))
        result.findings.extend(findings)
        for failure in failures:
            if isinstance(failure, dict):
                target = failure.get(self._failure_key) or failure.get("target") or failure.get("host", "")
                result.fail(target, str(failure.get("reason") or failure.get("error") or failure))
            else:
                result.fail("", str(failure))
        result.stats["duration_ms"] = timer.elapsed_ms
        return result


def _secret_scan(paths: list[str]):
    from collectors.secret_scanner import scan_tree

    findings, failures = [], []
    for path in paths:
        if not Path(path).is_dir():
            failures.append({"path": path, "reason": "not a directory"})
            continue
        findings.extend(scan_tree(path))
    return findings, failures


def _vault_scan(paths: list[str]):
    from collectors.vault_collector import scan_vault

    findings, failures = [], []
    for path in paths or [None]:
        found, errors = scan_vault(path)
        findings.extend(found)
        failures.extend({"path": str(path), "reason": e} for e in errors)
    return findings, failures


def _keystore_scan(paths):
    from collectors.keystore_scanner import scan_keystores
    return scan_keystores(paths)


def _tls_scan(targets):
    from collectors.tls_scanner import scan_tls_endpoints
    return scan_tls_endpoints(targets)


def _build() -> dict[str, Collector]:
    from collectors.binary_scanner import BinaryCollector
    from collectors.capture_collector import CaptureCollector
    from collectors.config_scanner import ConfigCollector
    from collectors.container_scanner import ContainerCollector
    from collectors.dependency_scanner import DependencyCollector
    from collectors.source_scanner import SourceCollector
    from collectors.ssh_scanner import SSHCollector

    collectors: list[Collector] = [
        SourceCollector(),
        DependencyCollector(),
        BinaryCollector(),
        ContainerCollector(),
        ConfigCollector(),
        _FunctionCollector("keystore", "held", "Keystores & certificates",
                           "PEM and PKCS#12 keystores: certificates and key metadata.", ("path",),
                           _keystore_scan),
        _FunctionCollector("secret", "built", "Key material in files",
                           "Private keys and credentials committed to a tree (fingerprints only).",
                           ("path", "repo"), _secret_scan),
        _FunctionCollector("vault", "held", "HSM / KMS / key managers",
                           "PKCS#11, KMIP and cloud KMS metadata exports.", ("path",), _vault_scan),
        _FunctionCollector("tls", "observed", "Live TLS endpoints",
                           "Handshakes against host:port targets: protocol, group, certificate chain.",
                           ("host",), _tls_scan, failure_key="target"),
        SSHCollector(),
        CaptureCollector(),
    ]
    return {c.name: c for c in collectors}


REGISTRY: dict[str, Collector] = _build()


def register(collector: Collector) -> None:
    """Add or replace a collector. Used by later work packages and by tests."""
    REGISTRY[collector.name] = collector


def describe() -> list[dict]:
    """The registry as data, for the API and the Scan screen."""
    return [
        {"name": c.name, "plane": c.plane, "label": c.label, "description": c.description,
         "target_kinds": list(c.target_kinds)}
        for c in REGISTRY.values()
    ]
