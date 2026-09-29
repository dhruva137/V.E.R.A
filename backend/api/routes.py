"""M6 - API surface over the collectors, scoring engine and regulatory mapper."""

from __future__ import annotations

import datetime
import io
import json
import math
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, File, HTTPException, Query, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

import store
from collectors import demo_estate
from collectors.binary_scanner import scan_binaries
from collectors.dependency_scanner import scan_dependencies
from collectors.config_scanner import scan_configs
from collectors.container_scanner import scan_images
from collectors.keystore_scanner import scan_keystores
from collectors.source_scanner import scan_source
from collectors.tls_scanner import scan_tls_endpoints
from engine import audit_chain, hybrid, recommendations
from engine.cbom import generate_cbom
from engine.cbom_import import cbom_to_findings
from engine.cbom_validate import validate_cbom
from engine.agility import agility_for
from engine.agility import summarise as agility_summary
from engine.dependencies import build_graph
from engine.expiry import expiry_for
from engine.expiry import summarise as expiry_summary
from engine.scan_job import output_digest
from engine.qirs import (
    PROFILES, assign_risk_level, dominant_axis, explain_asset, order_assets, score_assets,
)
from engine.regulatory import PERSONA_SEVERITY, deadline_point, deadline_table, map_regulatory
from engine.sensitivity import analyse_invariance, weight_sensitivity
from engine.threat_model import ThreatModel
from models.schemas import (
    CryptoAsset, DashboardSummary, HeatmapCell, MigrationRequest, RawCryptoFinding,
    RoadmapItem, ScanRequest, ScanResult, ScanSummary,
)
from report.generator import generate_board_memo

router = APIRouter()

# Paths are resolved relative to this file, not the working directory. The
# previous version used a bare "data/targets.json", so the server only worked
# when launched from inside backend/.
BACKEND_ROOT = Path(__file__).resolve().parent.parent
TARGETS_FILE = BACKEND_ROOT / "data" / "targets.json"
DEMO_ESTATE = BACKEND_ROOT.parent / "demo" / "estate" / "estate.yaml"


class _State:
    """Current in-memory scan, mirrored to SQLite for history and comparison."""

    def __init__(self):
        self.assets: list[CryptoAsset] = []
        self.cbom: dict = {}
        self.cbom_report: dict = {}
        self.scan_id: str = ""
        self.scan_timestamp: str = ""
        self.org_persona: str = "Banking"
        self.threat_model: ThreatModel | None = None
        self.scan_label: str = "Scanned Estate"
        # Per-collector output hashes for the signed manifest, and the signed
        # manifest itself, cached per (scan, profile) because signing is not free.
        self.inputs: list[dict] = []
        self.manifest_cache: dict = {}
        # From the last full scan (WP6): drift records, posture declarations,
        # identity-resolution stats and the estate register it ran against.
        self.drift: list[dict] = []
        self.declarations: list[dict] = []
        self.resolution: dict = {}
        self.estate: dict = {}

    def model(self) -> ThreatModel:
        if self.threat_model is None:
            self.threat_model = ThreatModel()
        return self.threat_model


state = _State()


def get_threat_model() -> ThreatModel:
    return state.model()


def _require_scan() -> list[CryptoAsset]:
    if not state.assets:
        raise HTTPException(
            status_code=409,
            detail="No scan data available. Run POST /api/scan/demo or /api/scan/tls first.",
        )
    return state.assets


def _asset_name(finding: RawCryptoFinding) -> str:
    """A readable label. Certificates lead with their subject CN."""
    # A collector that already knows the human name for a thing says so. Key
    # managers name their objects; deriving a label from a pkcs11:// URI when
    # the token already told us "atm-firmware-sign" throws that away.
    hinted = (finding.raw_details or {}).get("display_name")
    if isinstance(hinted, str) and hinted.strip():
        return hinted.strip()
    if finding.cert_subject:
        common_name = next(
            (
                part.split("=", 1)[1]
                for part in finding.cert_subject.split(",")
                if part.strip().upper().startswith("CN=")
            ),
            None,
        )
        if common_name:
            return common_name.strip()
        return finding.cert_subject
    if finding.key_exchange:
        return f"{finding.source_location} - {finding.key_exchange} key exchange"
    if finding.cipher_suite:
        return f"{finding.source_location} - {finding.cipher_suite}"
    if finding.algorithm:
        return f"{finding.source_location} - {finding.algorithm}"
    return finding.source_location


def process_findings(
    findings: list[RawCryptoFinding],
    duration: float,
    kind: str,
    label: str,
    org_persona: str,
    unreachable: list[dict] | None = None,
    targets_attempted: int = 0,
    merge: bool = False,
) -> ScanResult:
    """Run findings through the full pipeline and persist the result.

    `merge` adds the new findings to the current inventory instead of replacing
    it. A real estate is assembled from several collectors - TLS endpoints plus
    keystores plus configs - and a scan that silently discards everything found
    by the previous one makes that impossible. Replacing is still the default,
    because a repeated scan of the same scope should not double-count.

    Assets are keyed by (source_location, asset_class, algorithm/kex/suite) so
    rescanning the same endpoint updates it in place rather than duplicating.
    """
    assets = [
        CryptoAsset(**finding.model_dump(), name=_asset_name(finding))
        for finding in findings
    ]

    if merge and state.assets:
        def identity(asset: CryptoAsset):
            return (
                asset.source_location,
                asset.asset_class,
                asset.algorithm or asset.key_exchange or asset.cipher_suite,
            )

        incoming = {identity(a) for a in assets}
        retained = [a for a in state.assets if identity(a) not in incoming]
        assets = retained + assets

    model = state.model()
    assets = score_assets(assets, model)
    assets = map_regulatory(assets, org_persona=org_persona)
    for asset in assets:
        asset.risk_level = assign_risk_level(asset)
    assets = order_assets(assets, model)

    from engine.quantum_resources import current_version

    # One timestamp for the scan, reused by the CBOM, SARIF and the manifest so
    # that re-exporting the same scan is byte-identical.
    scan_timestamp = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()
    threat_version = current_version()["version"]
    cbom = generate_cbom(assets, org_name=label, timestamp=scan_timestamp, threat_model_version=threat_version)
    report = validate_cbom(cbom)
    if not merge:
        # A replacing scan makes drift from an earlier full scan stale.
        state.drift, state.declarations, state.resolution, state.estate = [], [], {}, {}

    scan_id = str(uuid.uuid4())
    state.assets = assets
    state.cbom = cbom
    state.cbom_report = report
    state.scan_id = scan_id
    state.scan_timestamp = scan_timestamp
    state.scan_label = label
    state.manifest_cache = {}
    state.inputs = [{"collector": kind, "target": label, "findings": len(findings),
                     "output_sha256": output_digest(findings)}]
    state.org_persona = org_persona

    summary = _build_dashboard().model_dump()
    summary["threat_model_version"] = threat_version
    audit_chain.append("scan", kind, {"scan_id": scan_id, "label": label, "assets": len(assets),
                                      "merge": merge, "cbom_serial": cbom["serialNumber"]})
    store.save_scan(
        scan_id=scan_id,
        kind=kind,
        label=label,
        org_persona=org_persona,
        assets=assets,
        cbom=cbom,
        summary=summary,
        cbom_valid=report["valid"],
    )

    vulnerable = sum(1 for a in assets if a.quantum_vulnerable)
    broken = sum(1 for a in assets if a.classically_broken)
    behind = sum(1 for a in assets if recommendations.behind(a))

    unreachable = unreachable or []
    return ScanResult(
        scan_id=scan_id,
        status="ok" if assets else "empty",
        message=(
            f"{len(assets)} cryptographic assets catalogued. {vulnerable} are "
            f"quantum-vulnerable, {broken} are already broken classically, and "
            f"{behind} cannot meet their statutory milestone even starting today."
            if assets
            else "No cryptographic assets were found."
        ),
        assets_found=len(assets),
        quantum_vulnerable=vulnerable,
        classically_broken=broken,
        negative_slack_count=behind,
        cbom_id=cbom.get("serialNumber", ""),
        cbom_valid=report["valid"],
        scan_duration_seconds=round(duration, 3),
        targets_attempted=targets_attempted,
        targets_reachable=max(targets_attempted - len(unreachable), 0),
        unreachable=unreachable,
    )


# --------------------------------------------------------------------------
# Scanning
# --------------------------------------------------------------------------


@router.post("/scan/demo", response_model=ScanResult)
def run_demo_scan(org_persona: str = Query("Banking")):
    """Load the synthetic target estate and score it."""
    start = datetime.datetime.now()
    findings = demo_estate.generate_estate()
    duration = (datetime.datetime.now() - start).total_seconds()
    return process_findings(
        findings, duration, kind="demo", label=demo_estate.ORG_NAME, org_persona=org_persona
    )


@router.post("/scan/clear")
def clear_estate():
    """Clear all loaded assets from the in-memory estate."""
    global state
    state = _State()
    return {"status": "cleared", "message": "Estate successfully cleared."}



@router.post("/scan/tls", response_model=ScanResult)
def run_tls_scan(request: ScanRequest | None = None):
    """Passive TLS handshake against real endpoints.

    `scan_type` used to be a required field, so the front end's `{targets: [...]}`
    body produced a 422 and this endpoint never worked. It now has a default.
    """
    start = datetime.datetime.now()

    targets = list(request.targets) if request and request.targets else []
    if not targets:
        try:
            targets = json.loads(TARGETS_FILE.read_text()).get("tls_targets", [])
        except (OSError, json.JSONDecodeError) as exc:
            raise HTTPException(
                status_code=500, detail=f"Could not read default target list: {exc}"
            ) from exc

    findings, unreachable = scan_tls_endpoints(targets)
    duration = (datetime.datetime.now() - start).total_seconds()

    if not findings:
        raise HTTPException(
            status_code=502,
            detail={
                "message": f"No endpoint out of {len(targets)} completed a TLS handshake.",
                "unreachable": unreachable,
            },
        )

    return process_findings(
        findings,
        duration,
        kind="tls",
        label=f"Live TLS scan ({len(targets)} targets)",
        org_persona=(request.org_persona if request else "Banking"),
        unreachable=unreachable,
        targets_attempted=len(targets),
        merge=bool(request and request.merge),
    )


@router.post("/scan/ssh", response_model=ScanResult)
def run_ssh_scan(request: ScanRequest):
    """Read the banner and KEXINIT of live SSH servers (`host` or `host:port`).

    Sends only its own identification line; see collectors/ssh_scanner.py.
    """
    from collectors.ssh_scanner import scan_ssh_endpoints

    if not request.targets:
        raise HTTPException(status_code=400, detail="Give at least one SSH target (host or host:port).")
    start = datetime.datetime.now()
    findings, unreachable = scan_ssh_endpoints(list(request.targets))
    if not findings:
        raise HTTPException(
            status_code=502,
            detail={"message": f"No SSH server out of {len(request.targets)} answered.", "unreachable": unreachable},
        )
    return process_findings(
        findings, (datetime.datetime.now() - start).total_seconds(), kind="ssh",
        label=f"Live SSH scan ({len(request.targets)} targets)", org_persona=request.org_persona,
        unreachable=unreachable, targets_attempted=len(request.targets), merge=request.merge,
    )


class FullScanTarget(BaseModel):
    kind: str = Field(..., description="path | repo | image | capture | vault | host")
    value: str
    system: Optional[str] = None
    host: Optional[str] = Field(None, description="host:port a config target describes")
    exposure: Optional[str] = Field(None, description="internet | internal")
    collectors: Optional[List[str]] = None


class FullScanRequest(BaseModel):
    targets: List[FullScanTarget] = Field(default_factory=list)
    estate: Optional[str] = Field(None, description="Path to an estate register (YAML), or 'demo'.")
    org_persona: str = "Banking"
    merge: bool = False
    wait: bool = Field(False, description="Run synchronously and return when done (tests, CLI).")
    project_id: Optional[str] = Field(None, description="File the finished scan under this project.")


@router.post("/scan/full")
def start_full_scan(request: FullScanRequest):
    """Start a scan across every surface a target needs. Returns a job id.

    Follow progress at `/api/scan/jobs/{id}/events` (server-sent events). Give
    either explicit `targets` or an `estate` register, or both.
    """
    from engine import estate as estate_register
    from engine import scan_job
    from engine.estate import Target

    targets: list[Target] = []
    declarations: list[dict] = []
    meta: dict = {}
    if request.estate:
        # "demo" names the bundled register, so the dashboard need not know where the repo lives.
        register = DEMO_ESTATE if request.estate == "demo" else Path(request.estate)
        if not register.is_file():
            raise HTTPException(status_code=400, detail=f"Estate register not found: {request.estate}")
        try:
            targets, declarations, meta = estate_register.load(register)
        except (ValueError, KeyError) as exc:
            raise HTTPException(status_code=400, detail=f"Estate register invalid: {exc}") from exc
    for t in request.targets:
        if t.kind not in scan_job.KIND_COLLECTORS:
            raise HTTPException(status_code=400, detail=f"Unknown target kind: {t.kind}")
        targets.append(Target(kind=t.kind, value=t.value, system=t.system, host=t.host,
                              exposure=t.exposure, collectors=t.collectors))
    if not targets:
        raise HTTPException(status_code=400, detail="Nothing to scan: give targets or an estate register.")

    job = run_full_scan(targets, declarations, meta, org_persona=request.org_persona,
                        merge=request.merge, wait=request.wait, project_id=request.project_id)
    return {"job_id": job.id, "status": job.status, "targets": len(targets), "estate": meta or None,
            "events_url": f"/api/scan/jobs/{job.id}/events", "result": job.result, "error": job.error}


def run_full_scan(targets, declarations: list[dict], meta: dict, *, org_persona: str,
                  merge: bool, wait: bool, project_id: str | None = None):
    """Start a scan job whose result replaces (or merges into) the scored estate.

    Shared by the endpoint above and the agent's `run_scan` tool, so a scan the
    agent starts and one the Scan screen starts leave the same state.
    """
    from engine import scan_job

    def finish(job, assets, decls, drift_records, resolution) -> dict:
        """Score the resolved assets and keep what the drift and discovery views read."""
        result = process_findings(
            assets, time.time() - job.created_at, kind="full",
            label=meta.get("name") or f"Full scan ({len(targets)} targets)",
            org_persona=org_persona, merge=merge,
        )
        state.drift, state.declarations = drift_records, decls
        state.resolution, state.estate = resolution, meta
        state.inputs = list(job.inputs)
        if project_id:
            from engine import projects

            projects.link_scan(project_id, result.scan_id)
        return {"scan_id": result.scan_id, "assets": result.assets_found,
                "quantum_vulnerable": result.quantum_vulnerable, "drift": len(drift_records),
                "cross_plane_assets": resolution.get("cross_plane_assets", 0)}

    return scan_job.start(targets, declarations, finish, run_async=not wait)


@router.get("/scan/current")
def get_current_scan():
    """Which scan the screens are showing, or none yet. Cheap enough for the top bar to poll."""
    if not state.assets:
        return {"scan": None}
    return {"scan": {"id": state.scan_id, "timestamp": state.scan_timestamp, "label": state.scan_label,
                     "estate": state.estate.get("name") or state.scan_label,
                     "synthetic": bool(state.estate.get("synthetic")), "assets": len(state.assets),
                     "persona": state.org_persona}}


@router.get("/scan/jobs")
def list_scan_jobs():
    from engine import scan_job

    return [job.summary() for job in reversed(scan_job.JOBS.values())]


@router.get("/scan/jobs/{job_id}")
def get_scan_job(job_id: str):
    from engine import scan_job

    job = scan_job.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="No such scan job.")
    return {**job.summary(), "event_log": job.events}


@router.get("/scan/jobs/{job_id}/events")
def stream_scan_job(job_id: str, since: int = Query(0, ge=0)):
    """Server-sent events: collector_started / collector_finished / resolved / drift / done."""
    from engine import scan_job

    job = scan_job.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="No such scan job.")
    return StreamingResponse(scan_job.stream(job, since), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@router.get("/scan/collectors")
def list_collectors():
    """Every registered collector, its plane, and which source grammars load here."""
    from collectors.registry import describe
    from collectors.source_scanner import grammar_status

    return {"collectors": describe(), "grammars": grammar_status()}


@router.get("/drift")
def get_drift(rule: Optional[str] = Query(None), severity: Optional[str] = Query(None)):
    """Contradictions between planes from the last full scan, most severe first."""
    from engine import drift as drift_engine

    records = [r for r in state.drift
               if (rule is None or r["rule"] == rule) and (severity is None or r["severity"] == severity)]
    return {"summary": drift_engine.summarise(state.drift), "records": records,
            "declarations": len(state.declarations), "estate": state.estate or None}


@router.post("/scan/local", response_model=ScanResult)
def run_local_scan(
    keystore_paths: list[str] = Query(default=[]),
    config_paths: list[str] = Query(default=[]),
    source_paths: list[str] = Query(default=[]),
    binary_paths: list[str] = Query(default=[]),
    dependency_paths: list[str] = Query(default=[]),
    image_paths: list[str] = Query(default=[]),
    org_persona: str = Query("Banking"),
):
    """Scan real keystores, configs, source trees, binaries and dependency manifests on this host."""
    start = datetime.datetime.now()
    findings: list[RawCryptoFinding] = []
    unreadable: list[dict] = []

    for paths, scanner in (
        (keystore_paths, scan_keystores),
        (config_paths, scan_configs),
        (source_paths, scan_source),
        (binary_paths, scan_binaries),
        (dependency_paths, scan_dependencies),
        (image_paths, scan_images),
    ):
        if paths:
            found, failures = scanner(paths)
            findings.extend(found)
            unreadable.extend(failures)

    if not findings:
        raise HTTPException(
            status_code=404,
            detail={
                "message": "No cryptographic material found at the supplied paths.",
                "unreadable": unreadable,
            },
        )

    duration = (datetime.datetime.now() - start).total_seconds()
    return process_findings(
        findings, duration, kind="local", label="Local filesystem scan",
        org_persona=org_persona, unreachable=unreadable,
    )


@router.post("/import/cbom", response_model=ScanResult)
async def import_cbom(file: UploadFile = File(...), org_persona: str = Query("Banking"),
                      merge: bool = Query(False)):
    """Score a CycloneDX CBOM produced by another tool.

    Discovery is commoditised and consolidating under the Linux Foundation, so
    the useful position is to consume other scanners' output rather than
    compete with it. Anything that emits CycloneDX 1.6 cryptographic-asset
    components - CBOMkit, Theia, or this tool's own export - can be ranked here
    without rescanning.
    """
    start = datetime.datetime.now()

    try:
        document = json.loads(await file.read())
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=400, detail=f"Not valid JSON: {exc}") from exc

    if document.get("bomFormat") != "CycloneDX":
        raise HTTPException(
            status_code=400,
            detail="Not a CycloneDX document. Expected bomFormat 'CycloneDX'.",
        )

    findings = cbom_to_findings(document)
    if not findings:
        raise HTTPException(
            status_code=422,
            detail=(
                "No cryptographic-asset components found. This reads CycloneDX "
                "components of type 'cryptographic-asset' with cryptoProperties."
            ),
        )

    duration = (datetime.datetime.now() - start).total_seconds()
    label = (
        document.get("metadata", {}).get("component", {}).get("name")
        or file.filename
        or "Imported CBOM"
    )
    return process_findings(
        findings, duration, kind="import", label=label,
        org_persona=org_persona, merge=merge,
    )


@router.get("/scan/targets")
def get_default_targets():
    try:
        return json.loads(TARGETS_FILE.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/scans", response_model=list[ScanSummary])
def list_scans(limit: int = Query(25, ge=1, le=100)):
    return store.list_scans(limit)


# --------------------------------------------------------------------------
# Assets
# --------------------------------------------------------------------------


@router.get("/assets", response_model=list[CryptoAsset])
def get_assets(
    risk_level: str | None = None,
    persona: str | None = None,
    source_type: str | None = None,
    asset_class: str | None = None,
    verdict: str | None = None,
    only_vulnerable: bool = False,
    search: str | None = None,
    limit: int = Query(2000, ge=1, le=5000),
):
    assets = _require_scan()

    def matches(asset: CryptoAsset) -> bool:
        if risk_level and asset.risk_level != risk_level:
            return False
        if persona and asset.persona != persona:
            return False
        if source_type and asset.source_type != source_type:
            return False
        if asset_class and asset.asset_class != asset_class:
            return False
        if verdict and asset.verdict != verdict:
            return False
        if only_vulnerable and not asset.quantum_vulnerable:
            return False
        if search:
            needle = search.lower()
            haystack = " ".join(
                filter(None, [asset.name, asset.source_location, asset.algorithm, asset.persona])
            ).lower()
            if needle not in haystack:
                return False
        return True

    return [a for a in assets if matches(a)][:limit]


@router.get("/assets/{asset_id}", response_model=CryptoAsset)
def get_asset(asset_id: str):
    for asset in _require_scan():
        if asset.id == asset_id:
            return asset
    raise HTTPException(status_code=404, detail="Asset not found")


@router.get("/assets/{asset_id}/explain")
def get_asset_explanation(asset_id: str):
    """Full auditable derivation - the 2:30 demo beat."""
    for asset in _require_scan():
        if asset.id == asset_id:
            return explain_asset(asset, state.model())
    raise HTTPException(status_code=404, detail="Asset not found")


# --------------------------------------------------------------------------
# Dashboard
# --------------------------------------------------------------------------


def _build_dashboard() -> DashboardSummary:
    assets = state.assets
    timestamp = state.scan_timestamp or datetime.datetime.now(datetime.timezone.utc).isoformat()

    if not assets:
        return DashboardSummary(
            total_assets=0, quantum_vulnerable=0, quantum_safe=0, classically_broken=0,
            grover_weakened=0, by_algorithm={}, by_verdict={}, by_risk_level={},
            by_persona={}, by_source_type={}, by_asset_class={}, avg_hndl=0.0,
            avg_tnfl=0.0, avg_qirs=0.0, max_qirs=0.0, negative_slack_count=0,
            worst_slack_months=0.0, scan_timestamp=timestamp, org_persona=state.org_persona,
        )

    def tally(key) -> dict[str, int]:
        counts: dict[str, int] = {}
        for asset in assets:
            value = key(asset)
            if value:
                counts[value] = counts.get(value, 0) + 1
        return dict(sorted(counts.items(), key=lambda kv: -kv[1]))

    vulnerable = [a for a in assets if a.quantum_vulnerable]
    top = max(assets, key=lambda a: a.qirs) if assets else None

    return DashboardSummary(
        total_assets=len(assets),
        quantum_vulnerable=len(vulnerable),
        quantum_safe=len(assets) - len(vulnerable),
        classically_broken=sum(1 for a in assets if a.classically_broken),
        grover_weakened=sum(1 for a in assets if a.grover_weakened),
        by_algorithm=tally(lambda a: a.algorithm or a.key_exchange or a.cipher_suite),
        by_verdict=tally(lambda a: a.verdict),
        by_risk_level=tally(lambda a: a.risk_level),
        by_persona=tally(lambda a: a.persona),
        by_source_type=tally(lambda a: a.source_type),
        by_asset_class=tally(lambda a: a.profile_label),
        avg_hndl=round(sum(a.h_score for a in assets) / len(assets), 6),
        avg_tnfl=round(sum(a.t_score for a in assets) / len(assets), 6),
        avg_qirs=round(sum(a.qirs for a in assets) / len(assets), 6),
        max_qirs=round(max(a.qirs for a in assets), 6),
        negative_slack_count=sum(1 for a in assets if recommendations.behind(a)),
        worst_slack_months=round(min((a.slack_months for a in assets if recommendations.behind(a)), default=0.0), 1),
        top_risk_asset_id=top.id if top else None,
        scan_timestamp=timestamp,
        scan_id=state.scan_id,
        org_persona=state.org_persona,
    )


@router.get("/overview")
def get_overview():
    """Everything the Overview screen shows, in one call: verdict, figures, do-next, DST track,
    systems, coverage and evidence status. Each figure names its source."""
    from collectors.registry import describe
    from engine import certin, overview, recommendations, risk_view, scan_job

    assets = _require_scan()
    recs = recommendations.recommend_all(assets)
    job = next((j for j in reversed(scan_job.JOBS.values())
                if (j.result or {}).get("scan_id") == state.scan_id), None)
    signed = _signed_manifest()
    return overview.build(
        assets,
        risk=risk_view.build(assets, state.model()),
        recommendations=recs,
        gated=recommendations.gated_register(assets),
        cost=_cost_estimate(recs["items"]),
        conformance=certin.conformance(state.cbom) if state.cbom else None,
        cbom_check={"spec": state.cbom.get("specVersion"), "valid": state.cbom_report.get("valid"),
                    "components": state.cbom_report.get("components_checked")},
        manifest={"alg": signed["signature"]["alg"], "signed_at": signed.get("created_at")},
        audit=audit_chain.default().verify(),
        resolution=state.resolution,
        inputs=state.inputs,
        events=job.events if job else [],
        registry=describe(),
        declarations=state.declarations,
        estate=state.estate,
        persona=state.org_persona,
        scan={"id": state.scan_id, "timestamp": state.scan_timestamp, "label": state.scan_label},
        drift=len(state.drift),
    )


@router.get("/dashboard", response_model=DashboardSummary)
def get_dashboard():
    return _build_dashboard()


@router.get("/heatmap", response_model=list[HeatmapCell])
def get_heatmap(buckets: int = Query(5, ge=3, le=10)):
    """Dual-axis HNDL x TNFL grid.

    Only quantum-vulnerable assets are placed. A quantum-safe asset scores
    (0, 0) on both axes, and letting a hundred of them pile into the bottom-left
    cell would swamp the colour scale and hide the distribution that matters.
    """
    # Consistent with every other data endpoint: no scan is a 409, not an empty
    # 200. Returning an empty grid made the page render a blank chart instead
    # of the "run a scan" prompt every other view shows.
    assets = [a for a in _require_scan() if a.quantum_vulnerable]

    # Both axes are bounded above by 1 - S_Z(horizon), which at realistic
    # horizons is well under 0.5, so a fixed 0-1 domain leaves most of the grid
    # permanently empty and squeezes the whole estate into two cells. The domain
    # is therefore the observed maximum rounded up to a tenth, floored at 0.2,
    # and returned in the bucket labels so a reader always knows the scale.
    observed = max((max(a.h_score, a.t_score) for a in assets), default=0.0)
    axis_max = max(math.ceil(observed * 10) / 10, 0.2)
    step = axis_max / buckets

    labels = [f"{i * step:.2f}-{(i + 1) * step:.2f}" for i in range(buckets)]

    cells: dict[tuple[int, int], HeatmapCell] = {}
    for h_index in range(buckets):
        for t_index in range(buckets):
            cells[(h_index, t_index)] = HeatmapCell(
                hndl_bucket=labels[h_index], tnfl_bucket=labels[t_index],
                hndl_index=h_index, tnfl_index=t_index,
                count=0, asset_ids=[], avg_qirs=0.0, axis_max=axis_max,
            )

    best: dict[tuple[int, int], tuple[float, str]] = {}
    for asset in assets:
        h_index = min(int(asset.h_score / step), buckets - 1)
        t_index = min(int(asset.t_score / step), buckets - 1)
        cell = cells[(h_index, t_index)]
        cell.count += 1
        cell.asset_ids.append(asset.id)
        cell.avg_qirs += asset.qirs
        if asset.qirs > best.get((h_index, t_index), (-1.0, ""))[0]:
            best[(h_index, t_index)] = (asset.qirs, asset.name)

    for key, cell in cells.items():
        if cell.count:
            cell.avg_qirs = round(cell.avg_qirs / cell.count, 6)
            cell.top_asset_name = best[key][1]

    return list(cells.values())


@router.get("/roadmap", response_model=list[RoadmapItem])
def get_roadmap():
    """Migration Gantt.

    Start dates are derived by working backwards from the deadline: an asset
    starts as late as it can while still finishing on time. Assets already
    behind start now, which is what makes the overrun visible on the chart.
    """
    now = datetime.datetime.now()
    current = now.year + (now.month - 1) / 12.0

    items: list[RoadmapItem] = []
    for asset in _require_scan():
        if not asset.quantum_vulnerable:
            continue

        due = deadline_point(asset.statutory_deadline_year)
        latest_start = due - asset.y
        start = max(min(latest_start, due), current)
        if asset.slack_months < 0:
            start = current
        end = start + asset.y
        # The milestone that binds this asset (engine.regulatory.binding_phase).
        phase = "high-priority" if asset.binding_phase == "high_priority" else "full"

        items.append(RoadmapItem(
            asset_id=asset.id,
            asset_name=asset.name,
            algorithm=asset.algorithm or asset.key_exchange or asset.cipher_suite or "Unknown",
            persona=asset.persona,
            asset_class=asset.profile_label,
            start_year=round(start, 3),
            end_year=round(end, 3),
            migration_start=_year_to_iso(start),
            migration_end=_year_to_iso(end),
            deadline_year=asset.statutory_deadline_year,
            slack_months=asset.slack_months,
            phase=phase,
            risk_level=asset.risk_level,
            qirs=asset.qirs,
            overruns_deadline=end > due,
        ))

    return sorted(items, key=lambda i: (i.slack_months, -i.qirs))


def _year_to_iso(fractional_year: float) -> str:
    """Fractional year to an ISO date, e.g. 2027.5 -> 2027-07-01."""
    year = int(fractional_year)
    remainder = fractional_year - year
    start = datetime.datetime(year, 1, 1)
    end = datetime.datetime(year + 1, 1, 1)
    return (start + (end - start) * remainder).replace(microsecond=0).isoformat()


# --------------------------------------------------------------------------
# CBOM, analysis and reporting
# --------------------------------------------------------------------------


@router.get("/cbom")
def get_cbom(spec: str = Query("1.7", description="CycloneDX spec version: 1.7 (default) or 1.6")):
    """The CBOM for the current scan. Byte-identical for the same scan and spec."""
    from fastapi.responses import Response

    from engine.cbom import SUPPORTED_SPECS, canonical_json
    from engine.quantum_resources import current_version

    if not state.cbom:
        raise HTTPException(status_code=409, detail="No scan data available. Run a scan first.")
    if spec not in SUPPORTED_SPECS:
        raise HTTPException(status_code=400, detail=f"spec must be one of {SUPPORTED_SPECS}")
    document = state.cbom if spec == state.cbom.get("specVersion") else generate_cbom(
        state.assets, org_name=getattr(state, "scan_label", "Scanned Estate"), spec=spec,
        timestamp=state.scan_timestamp, threat_model_version=current_version()["version"])
    audit_chain.append("export", "cbom", {"spec": spec, "serial": document["serialNumber"], "scan_id": state.scan_id})
    return Response(canonical_json(document), media_type="application/json")


@router.get("/certin-conformance")
def get_certin_conformance():
    """The current CBOM checked against CERT-In's minimum elements (BOM guidelines v2.0, Table 9)."""
    from engine import certin

    if not state.cbom:
        raise HTTPException(status_code=409, detail="No scan data available. Run a scan first.")
    return certin.conformance(state.cbom)


@router.get("/cbom/validate")
def get_cbom_validation():
    if not state.cbom:
        raise HTTPException(status_code=409, detail="No scan data available. Run a scan first.")
    return state.cbom_report


@router.get("/threat-model")
def get_threat_model_data(max_years: int = Query(30, ge=5, le=60)):
    """The survival ensemble, plus the versioned model: resources table, citations, clock."""
    from engine import mosca
    from engine.quantum_resources import describe

    data = state.model().get_ensemble_data(max_years=max_years)
    data["versioned"] = describe()
    data["clock"] = mosca.clock(mosca.current_year())
    data["crqc_arrival_years_from_report"] = mosca.arrival_years(state.model())
    return data


@router.get("/inventory")
def get_inventory():
    """One slim row per asset and the counts behind every filter (engine.inventory_view)."""
    from engine import inventory_view

    assets = _require_scan()
    recs = {r["asset_id"]: r for r in recommendations.recommend_all(assets)["items"]}
    behind_ids = {a.id for a in assets if recommendations.behind(a)}
    drift_ids = {i for record in state.drift for i in record.get("asset_ids", [])}
    rows = inventory_view.rows(assets, recs, behind_ids, drift_ids)
    return {"scan": {"id": state.scan_id, "timestamp": state.scan_timestamp, "label": state.scan_label},
            "rows": rows, "facets": inventory_view.facets(rows)}


@router.get("/assets/{asset_id}/panel")
def get_asset_panel(asset_id: str):
    """Everything the asset panel shows: summary, evidence, risk, fix, dependencies, history."""
    from engine import inventory_view

    assets = _require_scan()
    asset = next((a for a in assets if a.id == asset_id), None)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    profile = recommendations.active_profile()
    recs = recommendations.recommend_all(assets, profile)["items"]
    recommendation = next((r for r in recs if r["asset_id"] == asset_id), None)
    system = (asset.raw_details or {}).get("system")
    owner = next((d.get("owner") for d in state.declarations if d.get("kind") == "system" and d.get("name") == system),
                 None)
    return inventory_view.panel(
        asset,
        recommendation=recommendation,
        why_nothing="" if recommendation else recommendations.need_for(asset, profile)[1],
        cost_share=_cost_estimate(recs)["per_asset"].get(asset_id) if recommendation else None,
        reading=_mosca_reading(asset),
        explain=explain_asset(asset, state.model()),
        graph=build_graph(assets),
        drift_records=[r for r in state.drift if asset_id in r.get("asset_ids", [])],
        owner=owner,
        history=store.asset_history(asset_id, state.scan_label),
    )


def _mosca_reading(asset: CryptoAsset) -> dict:
    from engine import mosca

    reading = mosca.assess(asset, state.model())
    reading["asset"] = {"id": asset.id, "name": asset.name, "algorithm": asset.algorithm,
                        "key_size": asset.key_size, "asset_class": asset.asset_class,
                        "system": (asset.raw_details or {}).get("system")}
    reading["classification"] = (asset.raw_details or {}).get("classification")
    reading["y_basis"] = asset.profile_rationale
    return reading


@router.get("/mosca/{asset_id}")
def get_mosca(asset_id: str):
    """Mosca for one asset: X, Y and per-primitive Z with the source of each number."""
    asset = next((a for a in _require_scan() if a.id == asset_id), None)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    return _mosca_reading(asset)


@router.get("/recommendations")
def get_recommendations(profile: Optional[str] = Query(None, description="commercial | cnsa")):
    """A target, alternatives, cost and owner for every asset that needs work (PS clause iv)."""
    from engine import recommendations

    try:
        result = recommendations.recommend_all(_require_scan(), profile)
    except (ValueError, KeyError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    cost = _cost_estimate(result["items"])
    for item in result["items"]:
        item["cost_estimate"] = cost["per_asset"].get(item["asset_id"])
    result["cost"] = {k: v for k, v in cost.items() if k != "per_asset"}
    return result


def _cost_estimate(items: list[dict]) -> dict:
    """Declared-assumption cost of the recommendation items (engine.cost_model)."""
    from engine import cost_model

    locations = {a.id: a.source_location for a in state.assets}
    try:
        return cost_model.estimate(items, locations, state.estate.get("cost"), state.estate.get("register"))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Estate register: {exc}") from exc


@router.get("/cost")
def get_cost(profile: Optional[str] = Query(None, description="commercial | cnsa")):
    """Migration cost: changes x declared person-days x declared day rate, with every assumption."""
    from engine import recommendations

    try:
        items = recommendations.recommend_all(_require_scan(), profile)["items"]
    except (ValueError, KeyError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _cost_estimate(items)


@router.get("/recommendations/{asset_id}")
def get_recommendation(asset_id: str, profile: Optional[str] = Query(None)):
    from engine import recommendations

    asset = next((a for a in _require_scan() if a.id == asset_id), None)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    return recommendations.recommend(asset, profile) or {"asset_id": asset_id, "need": None,
                                                          "why": recommendations.need_for(asset, profile or recommendations.active_profile())[1]}


@router.get("/profile")
def get_assurance_profile():
    """The recommendation profile: commercial (NIST) or cnsa (CNSA 2.0, sovereign / defence)."""
    from engine import recommendations

    return {"profile": recommendations.active_profile(), "available": list(recommendations.PROFILES)}


@router.put("/profile")
def put_assurance_profile(body: dict):
    from engine import recommendations

    try:
        profile = recommendations.set_profile(str(body.get("profile", "")).lower())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    audit_chain.append("setting", "profile", {"profile": profile}, actor="operator")
    return {"profile": profile}


@router.get("/vendor-gated")
def get_vendor_gated():
    """HSM vendors and cloud providers that must ship PQC before these assets can move."""
    from engine import recommendations

    return {"register": recommendations.gated_register(_require_scan())}


@router.get("/procurement-clauses")
def get_procurement_clauses(organisation: str = Query("the Customer")):
    """Plain-language supplier clauses per gated register entry. Drafts for legal review."""
    from engine import recommendations

    return {"clauses": recommendations.procurement_clauses(_require_scan(), organisation)}


@router.get("/detector/live")
def detector_live():
    """Run the shipped detector now on the bundled stripped programs (demo/detector/), changing nothing.

    Two SipHash builds that no signature layer recognises and two programs with no cryptography, each scanned
    through the same path a user's scan takes (collectors.binary_scanner.scan_blob). Ground truth comes from the
    unstripped twin of each link (demo/detector/manifest.json), so the screen can say right or wrong.
    """
    from collectors.binary_scanner import scan_blob

    folder = BACKEND_ROOT.parent / "demo" / "detector"
    manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    out = []
    for name, info in manifest.items():
        path = folder / f"{name}.stripped"
        t = time.perf_counter()
        res = scan_blob(path.read_bytes(), str(path))
        seconds = time.perf_counter() - t
        learned = next((f for f in res.findings if "layer:learned_function" in f.tags), None)
        d = learned.raw_details if learned else {}
        out.append({
            "name": name, "what": info["what"], "contains_crypto": info["contains_crypto"], "size": path.stat().st_size,
            "flagged": bool(res.findings), "found_by": sorted({x for f in res.findings for x in f.raw_details.get("layers", [])}),
            "q_value": d.get("detection_q_value"), "alpha": d.get("detection_alpha"), "isa": d.get("detection_isa"),
            "functions_scored": res.stats.get("functions_scored", 0), "functions_selected": d.get("functions_selected", 0),
            "selected": d.get("selected_functions", [])[:3], "seconds": round(seconds, 2),
        })
    return {"programs": out, "correct": sum(p["flagged"] == p["contains_crypto"] for p in out), "total": len(out)}


@router.get("/detector")
def get_detector():
    """The binary detector's research evidence, read from research/results/ (see research/README.md).

    Returned as the files say, each block with its file name and commit, so the Evidence screen can show where
    every number comes from. Nothing is recomputed; a missing file is reported as missing.
    """
    res_dir = BACKEND_ROOT.parent / "research" / "results"

    def read(name: str) -> dict | None:
        path = res_dir / name
        return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None

    v11, e2e, cross, sim = read("v1_1_detector.json"), read("e2e.json"), read("v2_cross_isa.json"), read("theory_sim.json")
    models, scale, shipped = read("v2_models.json"), read("v2_scale.json"), read("e2e_product.json")
    out: dict = {"missing": [n for n, d in (("v1_1_detector.json", v11), ("e2e.json", e2e), ("v2_cross_isa.json", cross),
                                            ("theory_sim.json", sim), ("v2_models.json", models)) if d is None]}
    if v11:
        sealed = v11["sealed"]
        out["threshold_vs_conformal"] = {
            "file": "research/results/v1_1_detector.json", "commit": v11["commit"],
            "rows": [{"prevalence": k.split("=")[1], "fixed_threshold_fdp": v["fixed@0.9"]["mean_fdp"],
                      "conformal_fdp": v["bh@0.1"]["mean_fdp"], "conformal_power": v["bh@0.1"]["mean_power"]}
                     for k, v in sealed["conformal"].items()],
            "sealed_roc_auc": sealed["roc_auc"], "per_arch": sealed["per_arch"],
        }
    if e2e:
        out["binaries"] = {"file": "research/results/e2e.json", "commit": e2e["commit"], "alpha": e2e["alpha"],
                           "calibration_n": e2e["calibration_n"], "programs": [
                               {"name": k, "arch": p["arch"], "contains_crypto": p["contains_crypto"],
                                "train_overlap": p["train_overlap"], "functions": p["functions_scored"],
                                "signatures": p["flags"]["vera_signatures"], "pqc_table": p["flags"]["ntt"],
                                "findcrypt3": p["flags"]["findcrypt3"], "min_q": p.get("min_q"),
                                "boundary_recall": p["boundary_recall"]} for k, p in sorted(e2e["programs"].items())]}
    if shipped:
        # The shipped model and calibration, through the product's own scan path (scan_blob): the numbers to quote.
        out["shipped"] = {"file": "research/results/e2e_product.json", "commit": shipped["commit"],
                          "path": shipped["path"], "summary": shipped["summary_independent"], "programs": [
                              {"name": k, "contains_crypto": p["contains_crypto"], "train_overlap": p["train_overlap"],
                               "flagged": p["flagged"], "layers": p["layers"], "algorithms": p["algorithms"],
                               "learned_q": p["learned_q"], "seconds": p["seconds"]}
                              for k, p in sorted(shipped["programs"].items())]}
    if cross:
        out["per_isa"] = {"file": "research/results/v2_cross_isa.json", "commit": cross["commit"], "model": cross["model"],
                          "alpha": cross["alpha"], "matrix": cross["matrix"]}
    if sim:
        out["theory"] = {"file": "research/results/theory_sim.json", "commit": sim["commit"], "reps": sim["reps"],
                         "violations": len(sim["violations"]), "cells": len(sim["prop1"]) + len(sim["thm2"])}
    if models:
        out["architecture"] = {"file": "research/results/v2_models.json", "commit": models["commit"],
                               "selected_on_dev": models["selected_on_dev"], "ship_rule": models["ship_rule"]}
    if scale:
        out["scale"] = {"file": "research/results/v2_scale.json", "commit": scale["commit"],
                        "sealed_b": scale.get("A2_sealed_b"), "by_opt": scale.get("B5_sealed_by_opt")}
    return out


@router.get("/method")
def get_method():
    """The measured benchmarks behind the method, read from their result files in bench/.

    Each block is the file's own summary, with its measurement date, or an
    explicit "not measured" when the file is absent. Nothing here is recomputed.
    """
    bench_dir = BACKEND_ROOT.parent / "bench"

    def read(name: str) -> dict | None:
        path = bench_dir / name
        return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None

    detection = read("results.json")
    agent = read("agent_results.json")
    return {
        "detection": None if detection is None else {
            "file": "bench/results.json", "measured_at": detection.get("measured_at"),
            "git_commit": detection.get("git_commit"), "corpus": detection.get("corpus"),
            "matching": detection.get("matching"), "first_run": detection.get("first_run"),
            "splits": detection.get("splits"), "corrections": detection.get("corrections_after_first_run"),
            "caveats": detection.get("caveats"),
        },
        "agent": None if agent is None else {
            "file": "bench/agent_results.json", "measured_at": agent.get("measured_at"), "model": agent.get("model"),
            "prompts": agent.get("prompts"), "repeats": agent.get("repeats"), "summary": agent.get("summary"),
            "caveat": agent.get("caveat"),
        },
    }


@router.get("/bench")
def get_bench():
    """Measured PQC latency on the demo host (bench/pqc_bench.json), or an explicit 'not measured'."""
    from engine import hybrid, recommendations

    record = recommendations.bench()
    sizes = [vars(s) for s in hybrid.KEM_SIZES + hybrid.SIGNATURE_SIZES]
    if record is None:
        return {"measured": False, "note": "Not measured on this host. Run: python bench/pqc_bench.py",
                "results": [], "sizes": sizes}
    return {**record, "sizes": sizes}


@router.get("/risk")
def get_risk_view(doubling: Optional[float] = Query(None, ge=0.5, le=10.0,
                                                    description="What-if doubling time D in years")):
    """When each primitive breaks and each asset's Mosca margin; `doubling` is a what-if, never stored."""
    from engine import risk_view

    return risk_view.build(_require_scan(), state.model(), doubling=doubling)


@router.get("/mosca")
def get_mosca_summary():
    """Mosca categories across the estate, by system and by axis."""
    counts: Dict[str, int] = {}
    by_system: Dict[str, Dict[str, int]] = {}
    for asset in _require_scan():
        category = asset.mosca_category or "not_applicable"
        counts[category] = counts.get(category, 0) + 1
        system = (asset.raw_details or {}).get("system") or "unassigned"
        by_system.setdefault(system, {})
        by_system[system][category] = by_system[system].get(category, 0) + 1
    return {"categories": counts, "by_system": by_system}


@router.get("/sensitivity")
def get_sensitivity():
    """Ordering invariance across survival families - blueprint Claim 2."""
    assets = _require_scan()
    return {
        "invariance": analyse_invariance(assets),
        "weights": weight_sensitivity(assets),
    }


@router.get("/readiness")
def get_readiness():
    """What can actually be done to this estate, and what is already overdue.

    Three questions the risk score does not answer: what expires before the
    quantum deadline ever arrives, how much of the estate is changeable today
    versus blocked on someone else, and how much of it hangs off a single trust
    anchor.

    Returns aggregates and short worst-first lists only. Never the estate - a
    dashboard needs numbers, and an endpoint that can return every asset is the
    one that falls over first at scale.
    """
    assets = _require_scan()

    # Transitive dependent counts come from the same graph the dependency page
    # renders, so an expiring trust anchor is ranked above an expiring leaf.
    graph = build_graph(assets)
    dependents = {node["id"]: node.get("dependents", 0) for node in graph.get("nodes", [])}

    total = len(assets)
    top_anchors = graph.get("stats", {}).get("most_depended_on", [])[:3]
    concentration = []
    for anchor in top_anchors:
        concentration.append({
            **anchor,
            "pct_of_estate": round(100.0 * anchor.get("dependents", 0) / total, 1)
            if total else 0.0,
        })

    unowned = [a for a in assets if not (a.owner or "").strip()]
    unresolved = [a for a in assets if a.verdict == "unknown"]

    return {
        "expiry": expiry_summary(assets, dependents=dependents),
        "agility": agility_summary(assets),
        "concentration": {
            "top": concentration,
            # The single number worth putting on a dashboard: how much of the
            # estate one forged anchor would take with it.
            "worst_pct": concentration[0]["pct_of_estate"] if concentration else 0.0,
        },
        "ownership": {
            "unowned": len(unowned),
            "owned": total - len(unowned),
            "unowned_pct": round(100.0 * len(unowned) / total, 1) if total else 0.0,
        },
        "unresolved": {
            "count": len(unresolved),
            "note": (
                "Cryptography selected at runtime that static analysis cannot resolve. "
                "Reported rather than guessed at."
            ),
        },
        "total_assets": total,
    }


@router.get("/regulatory")
def get_regulatory_reference():
    return {
        **deadline_table(),
        "personas": PERSONA_SEVERITY,
        "current_org_persona": state.org_persona,
    }


@router.get("/policy-profiles")
def get_policy_profiles():
    """The QIRS policy inputs per asset class, so every default is inspectable."""
    return {
        "profiles": [
            {
                "key": key,
                "label": profile.label,
                "x_c": profile.x_c, "x_i": profile.x_i, "y": profile.y,
                "s": profile.s, "e": profile.e, "c": profile.c,
                "rationale": profile.rationale,
            }
            for key, profile in PROFILES.items()
        ],
        "note": (
            "These are policy inputs, not measurements. Each is a stated assumption "
            "an operator is expected to replace with their own data classification and "
            "effort estimates."
        ),
    }


# --------------------------------------------------------------------------
# Evidence: SARIF, signed manifest, audit chain, delta (WP9)
# --------------------------------------------------------------------------


def _sarif_document() -> dict:
    from engine.sarif import generate_sarif

    return generate_sarif(_require_scan(), state.drift)


@router.get("/sarif")
def get_sarif():
    """SARIF 2.1.0 for CI gating: one rule per finding class, levels from risk."""
    from fastapi.responses import Response

    from engine.cbom import canonical_json

    document = _sarif_document()
    audit_chain.append("export", "sarif", {"scan_id": state.scan_id, "results": len(document["runs"][0]["results"])})
    return Response(canonical_json(document), media_type="application/sarif+json")


@router.get("/sarif/validate")
def validate_sarif_export():
    from engine.schema_validation import validate_sarif

    errors = validate_sarif(_sarif_document())
    return {"valid": not errors, "errors": errors, "schema": "OASIS SARIF 2.1.0 (errata 01, vendored)"}


def _manifest_inputs() -> list[dict]:
    return getattr(state, "inputs", None) or []


@router.get("/manifest")
def get_manifest():
    """The signed manifest for the current scan (ML-DSA-65, or a labelled Ed25519 fallback)."""
    signed = _signed_manifest()
    audit_chain.append("export", "manifest", {"scan_id": state.scan_id, "alg": signed["signature"]["alg"]})
    return signed


def _signed_manifest() -> dict:
    """The current scan's signed manifest, built once per (scan, profile) and cached."""
    from engine import manifest as manifest_engine
    from engine import recommendations
    from engine.cbom import canonical_json
    from engine.core.policy import get_current
    from engine.quantum_resources import current_version, table_hash

    assets = _require_scan()
    profile = recommendations.active_profile()
    cache_key = (state.scan_id, profile)
    cached = getattr(state, "manifest_cache", {})
    if cache_key not in cached:
        cbom_text = canonical_json(state.cbom)
        sarif_text = canonical_json(_sarif_document())
        unsigned = manifest_engine.build(
            scan={"scan_id": state.scan_id, "label": state.scan_label, "timestamp": state.scan_timestamp,
                  "assets": len(assets), "cbom_spec": state.cbom.get("specVersion"),
                  "cbom_serial": state.cbom.get("serialNumber")},
            inputs=_manifest_inputs(), cbom_text=cbom_text, sarif_text=sarif_text,
            threat_model={"version": current_version()["version"], "resources_table_hash": table_hash()},
            profile=profile, policy=get_current().to_dict(), created_at=state.scan_timestamp,
        )
        cached = {cache_key: manifest_engine.sign(unsigned)}
        state.manifest_cache = cached
    return cached[cache_key]


@router.post("/manifest/verify")
def verify_manifest(body: dict):
    """Verify a manifest's signature, and whether its CBOM hash matches the current scan's CBOM."""
    from engine import manifest as manifest_engine
    from engine.cbom import canonical_json

    manifest = body.get("manifest", body)
    result = manifest_engine.verify(manifest, manifest_engine.local_public_key()["public_key_pem"])
    if state.cbom and manifest.get("cbom_sha256"):
        result["cbom_matches_current_scan"] = (
            manifest["cbom_sha256"] == manifest_engine.sha256_hex(canonical_json(state.cbom)))
    return result


@router.get("/manifest/public-key")
def get_manifest_public_key():
    from engine import manifest as manifest_engine

    return manifest_engine.local_public_key()


@router.get("/report/ntro")
def get_ntro_report():
    """The NTRO / CII assessment report (PDF): executive page to signed evidence."""
    from engine import manifest as manifest_engine
    from engine import recommendations
    from engine.classification import table as data_class_table
    from engine.quantum_resources import current_version, describe
    from report.ntro import generate_ntro_report

    assets = _require_scan()
    manifest = get_manifest()
    described = describe()
    pdf = generate_ntro_report(
        assets=assets, estate=state.estate or None,
        scan={"scan_id": state.scan_id, "label": state.scan_label, "timestamp": state.scan_timestamp,
              "cbom_spec": state.cbom.get("specVersion")},
        recommendations=recommendations.recommend_all(assets), gated=recommendations.gated_register(assets),
        clauses=recommendations.procurement_clauses(assets), drift=state.drift,
        threat_model={**current_version(), "doubling_years": described["doubling_years"], "rows": described["rows"]},
        manifest=manifest, manifest_check=manifest_engine.verify(manifest, manifest["signature"]["public_key_pem"]),
        citations=recommendations.rules()["citations"], data_classes=data_class_table()["classes"],
    )
    audit_chain.append("export", "ntro_report", {"scan_id": state.scan_id, "bytes": len(pdf)})
    return StreamingResponse(io.BytesIO(pdf), media_type="application/pdf",
                             headers={"Content-Disposition": 'attachment; filename="vera-ntro-report.pdf"'})


@router.get("/audit/verify")
def verify_audit_chain():
    """Walk the tamper-evident audit chain; `first_broken` is the first entry that fails."""
    return audit_chain.default().verify()


@router.get("/audit/chain")
def get_audit_chain(limit: int = Query(50, ge=1, le=500)):
    chain = audit_chain.default()
    return {"entries": list(reversed(chain.entries(limit))), "verify": chain.verify()}


@router.get("/delta")
def get_delta(from_scan: Optional[str] = Query(None, alias="from"), to_scan: Optional[str] = Query(None, alias="to")):
    """Added / removed / changed assets, migration progress, and why scores moved."""
    from engine import delta

    scans = store.list_scans(limit=100)
    to_id = to_scan or state.scan_id or (scans[0]["scan_id"] if scans else None)
    if from_scan is None:
        earlier = [s for s in scans if s["scan_id"] != to_id]
        from_scan = earlier[0]["scan_id"] if earlier else None
    if not to_id or not from_scan:
        raise HTTPException(status_code=409, detail="Need two stored scans to compare.")
    before, after = store.get_scan(from_scan), store.get_scan(to_id)
    if before is None or after is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return delta.compare(before, after)


@router.get("/benchmark")
def get_benchmark(measure_host: str | None = Query(None)):
    """PQC size table, plus a real handshake measurement if a host is given."""
    result = hybrid.benchmark_table()
    if measure_host:
        result["measured_handshake"] = hybrid.measure_classical_handshake(measure_host)
    return result


def commit_migration(result: dict) -> dict:
    """Settle the estate after an in-place migration.

    hybrid.migrate rewrites and rescores the assets it selected, but the estate
    around them is now stale: risk levels were assigned against the old scores,
    the priority order has moved, and the CBOM still describes the pre-migration
    algorithms. This does that settling and persists the result as a new scan.

    Shared by the harness endpoint and the agent, so an agent-driven migration
    and an operator-driven one cannot leave the estate in different shapes. That
    divergence is the kind of bug that only shows up as two pages disagreeing
    during a demo.
    """
    if not result.get("migrated"):
        return result

    for asset in state.assets:
        asset.risk_level = assign_risk_level(asset)
    state.assets = order_assets(state.assets, state.model())
    state.cbom = generate_cbom(state.assets, org_name="Post-migration estate")
    state.cbom_report = validate_cbom(state.cbom)
    state.scan_id = str(uuid.uuid4())
    state.scan_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    store.save_scan(
        scan_id=state.scan_id, kind="migration",
        label=f"After migrating {result.get('target', 'selection')}",
        org_persona=state.org_persona, assets=state.assets, cbom=state.cbom,
        summary=_build_dashboard().model_dump(), cbom_valid=state.cbom_report["valid"],
    )
    result["scan_id"] = state.scan_id
    return result


@router.post("/harness/migrate")
def run_migration(request: MigrationRequest):
    """M8 - migrate assets in place and report the before/after.

    `asset_id` selects one row exactly (single-asset preview). Otherwise `target`
    is a substring over source_location, matching the original harness behaviour.
    """
    assets = _require_scan()
    if request.asset_id:
        chosen = next((a for a in assets if a.id == request.asset_id), None)
        if chosen is None:
            raise HTTPException(status_code=404, detail=f"No asset {request.asset_id!r}.")
        if not chosen.quantum_vulnerable:
            return {
                "migrated": 0,
                "message": f"{chosen.name} is not quantum-vulnerable; nothing to migrate.",
                "changes": [],
            }
        result = hybrid.migrate(
            [chosen], state.model(), strategy=request.strategy,
        )
        result["target"] = chosen.name
        return commit_migration(result)

    result = hybrid.migrate(
        assets,
        state.model(),
        target=request.target,
        asset_classes=request.asset_classes,
        strategy=request.strategy,
    )
    return commit_migration(result)


@router.get("/report/pdf")
def get_report_pdf():
    assets = _require_scan()
    pdf = generate_board_memo(
        assets, _build_dashboard(), state.cbom_report, state.model()
    )
    filename = f"vera_board_memo_{datetime.date.today().isoformat()}.pdf"
    return StreamingResponse(
        io.BytesIO(pdf),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/estate/metadata")
def get_estate_metadata():
    return demo_estate.estate_metadata()


@router.get("/dependencies")
def get_dependency_graph():
    """Dependency graph over the current estate.

    A read-only projection: it recomputes nothing and changes no score. See
    engine.dependencies for where each edge comes from and which are observed
    versus inferred.
    """
    return build_graph(_require_scan())


@router.get("/axis-extremes")
def get_axis_extremes(count: int = Query(5, ge=1, le=20)):
    """The assets each axis surfaces, side by side.

    This is the dual-axis argument in its most direct form: the top of one axis
    and the top of the other are different populations. A single-axis tool shows
    one of these lists and misses the other entirely.
    """
    assets = [a for a in _require_scan() if a.quantum_vulnerable]

    def summarise(asset: CryptoAsset) -> dict:
        axis, value = dominant_axis(asset)
        return {
            "id": asset.id, "name": asset.name, "asset_class": asset.profile_label,
            "h_score": asset.h_score, "t_score": asset.t_score, "qirs": asset.qirs,
            "dominant_axis": axis, "dominant_value": value,
            "x_c": asset.x_c, "x_i": asset.x_i, "y": asset.y,
        }

    by_h = sorted(assets, key=lambda a: -a.h_score)[:count]
    by_t = sorted(assets, key=lambda a: -a.t_score)[:count]
    overlap = {a.id for a in by_h} & {a.id for a in by_t}

    return {
        "top_hndl": [summarise(a) for a in by_h],
        "top_tnfl": [summarise(a) for a in by_t],
        "overlap_count": len(overlap),
        "interpretation": (
            f"The top {count} assets on each axis share {len(overlap)} members. "
            "Confidentiality risk concentrates in ephemeral key exchange, where the "
            "horizon is X_c + Y and grows without bound as migration slips. Integrity "
            "risk concentrates in long-lived signing anchors, where the horizon is "
            "min(X_i, Y) and saturates. Scoring one axis ranks the other population "
            "wrongly, which is the whole argument for carrying both."
        ),
    }


# --------------------------------------------------------------------------
# LLM Integration
# --------------------------------------------------------------------------

@router.get('/llm/config')
def get_llm_config():
    """Current LLM configuration. The API key is never returned."""
    from engine.llm_bridge import get_config
    return get_config().to_dict()


@router.post('/llm/config')
def update_llm_config(body: dict):
    """Update the provider configuration at runtime.

    Only the fields present in the body are changed, so the dashboard can save a
    model choice without resending the API key it was never given.
    """
    from engine.llm_bridge import get_config
    config = get_config()
    config.update(**body)
    # Record which settings changed, never their values (an API key may be among them).
    audit_chain.append("setting", "llm_config", {"fields": sorted(body)}, actor="operator")
    return config.to_dict()


@router.delete('/llm/config/key')
def clear_llm_key():
    """Forget the API key without clearing the rest of the configuration."""
    from engine.llm_bridge import get_config
    config = get_config()
    config.clear_key()
    return config.to_dict()


@router.get('/llm/models')
async def list_llm_models():
    """Models the configured endpoint actually offers.

    Backs the Load models button. A 502 here is a real upstream failure and the
    body carries the remedy, so the UI can show what to do rather than "error".
    """
    from engine.llm_bridge import LLMError, list_models
    try:
        return await list_models()
    except LLMError as exc:
        raise HTTPException(status_code=502, detail=exc.to_dict()) from exc


@router.post('/llm/test')
async def test_llm():
    """Round-trip the configured model and report latency."""
    from engine.llm_bridge import LLMError, test_connection
    try:
        return await test_connection()
    except LLMError as exc:
        raise HTTPException(status_code=502, detail=exc.to_dict()) from exc


@router.get('/assets/{asset_id}/narrative')
async def get_asset_narrative(asset_id: str):
    """AI-generated threat narrative for an asset."""
    from engine.llm_bridge import generate_threat_narrative
    for asset in _require_scan():
        if asset.id == asset_id:
            asset_data = asset.model_dump()
            regulatory_context = {
                'persona': asset.persona,
                'deadline_year': asset.statutory_deadline_year,
                'binding_phase': asset.binding_phase,
            }
            return await generate_threat_narrative(asset_data, regulatory_context)
    raise HTTPException(status_code=404, detail='Asset not found')


@router.get('/assets/{asset_id}/remediation')
async def get_asset_remediation(asset_id: str):
    """AI-generated remediation steps for an asset."""
    from engine.llm_bridge import generate_remediation_steps
    for asset in _require_scan():
        if asset.id == asset_id:
            return await generate_remediation_steps(asset.model_dump())
    raise HTTPException(status_code=404, detail='Asset not found')



# --------------------------------------------------------------------------
# Enterprise Asset Management
# --------------------------------------------------------------------------

@router.post('/assets/register', response_model=ScanResult)
def register_manual_assets(
    assets: list,  # list of ManualAssetInput dicts
    org_persona: str = Query('Banking'),
):
    """Register assets manually without scanning.
    
    Designed for enterprise use: organizations input their cryptographic
    inventory from internal records, spreadsheets, or knowledge that no
    scanner can reach (HSM configurations, vendor-managed components,
    offline systems).
    """
    import datetime
    from engine.asset_manager import ManualAssetInput, manual_to_raw
    
    start = datetime.datetime.now()
    findings = []
    for item in assets:
        parsed = ManualAssetInput(**item) if isinstance(item, dict) else item
        raw = manual_to_raw(parsed)
        findings.append(RawCryptoFinding(**raw))
    
    if not findings:
        raise HTTPException(status_code=400, detail='No assets provided')
    
    duration = (datetime.datetime.now() - start).total_seconds()
    return process_findings(
        findings, duration, kind='manual', label=f'Manual registration ({len(findings)} assets)',
        org_persona=org_persona, merge=True,
    )


@router.post('/assets/import-csv', response_model=ScanResult)
async def import_csv_assets(
    file: UploadFile = File(...),
    org_persona: str = Query('Banking'),
):
    """Import assets from a CSV file.
    
    Accepts flexible column names (see engine.asset_manager.CSV_COLUMN_MAP).
    Minimum required: a 'name' or 'source_location' column.
    """
    import datetime
    from engine.asset_manager import parse_csv_assets, manual_to_raw, ManualAssetInput
    
    start = datetime.datetime.now()
    try:
        content = (await file.read()).decode('utf-8-sig')  # Handle BOM from Excel
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=400, detail=f'File is not valid UTF-8 text: {exc}') from exc
    
    assets, errors = parse_csv_assets(content)
    if not assets:
        raise HTTPException(
            status_code=422,
            detail={'message': 'No valid assets found in CSV', 'errors': errors},
        )
    
    findings = [RawCryptoFinding(**manual_to_raw(a)) for a in assets]
    duration = (datetime.datetime.now() - start).total_seconds()
    
    result = process_findings(
        findings, duration, kind='csv-import',
        label=f'CSV import: {file.filename or "upload"} ({len(findings)} assets)',
        org_persona=org_persona, merge=True,
    )
    # Attach parse errors so the UI can show partial import feedback
    result_dict = result.model_dump()
    result_dict['parse_errors'] = errors
    return result_dict


@router.get('/asset-classes')
def get_asset_classes():
    """Available asset class keys for the registration form."""
    return {
        'classes': [
            {'key': key, 'label': p.label, 'rationale': p.rationale}
            for key, p in PROFILES.items()
        ]
    }

@router.get('/analytics')
def get_analytics():
    """Estate-wide analytics for data-driven decision making."""
    assets = _require_scan()
    model = state.model()
    
    # Risk distribution histogram
    risk_bins = {'0.00-0.05': 0, '0.05-0.10': 0, '0.10-0.15': 0, '0.15-0.20': 0, '0.20-0.30': 0, '0.30+': 0}
    for a in assets:
        if a.qirs < 0.05: risk_bins['0.00-0.05'] += 1
        elif a.qirs < 0.10: risk_bins['0.05-0.10'] += 1
        elif a.qirs < 0.15: risk_bins['0.10-0.15'] += 1
        elif a.qirs < 0.20: risk_bins['0.15-0.20'] += 1
        elif a.qirs < 0.30: risk_bins['0.20-0.30'] += 1
        else: risk_bins['0.30+'] += 1
    
    # Axis scatter data
    scatter = [{'id': a.id, 'name': a.name, 'h': round(a.h_score, 4), 't': round(a.t_score, 4), 'qirs': round(a.qirs, 4), 'class': a.profile_label, 'vulnerable': a.quantum_vulnerable, 'slack': a.slack_months} for a in assets if a.quantum_vulnerable]
    
    # Migration effort distribution
    effort_dist = {}
    for a in assets:
        if a.quantum_vulnerable:
            bucket = f'{a.y:.1f}y'
            effort_dist[bucket] = effort_dist.get(bucket, 0) + 1
    
    # Slack distribution
    slack_positive = sum(1 for a in assets if a.slack_months >= 0 and a.quantum_vulnerable)
    slack_negative = sum(1 for a in assets if a.slack_months < 0 and a.quantum_vulnerable)
    slack_critical = sum(1 for a in assets if a.slack_months < -12 and a.quantum_vulnerable)
    
    # Key size distribution
    key_sizes = {}
    for a in assets:
        if a.key_size:
            label = f'{a.key_size}-bit'
            key_sizes[label] = key_sizes.get(label, 0) + 1
    
    # Verdict breakdown with details
    verdicts = {}
    for a in assets:
        v = a.verdict or 'unknown'
        if v not in verdicts:
            verdicts[v] = {'count': 0, 'avg_qirs': 0, 'assets': []}
        verdicts[v]['count'] += 1
        verdicts[v]['avg_qirs'] += a.qirs
    for v in verdicts:
        if verdicts[v]['count']:
            verdicts[v]['avg_qirs'] = round(verdicts[v]['avg_qirs'] / verdicts[v]['count'], 4)
    
    # HNDL vs TNFL dominance
    hndl_dominant = sum(1 for a in assets if a.quantum_vulnerable and a.h_score > a.t_score)
    tnfl_dominant = sum(1 for a in assets if a.quantum_vulnerable and a.t_score > a.h_score)
    balanced = sum(1 for a in assets if a.quantum_vulnerable and abs(a.h_score - a.t_score) < 0.01)
    
    # Source type breakdown with risk
    source_risk = {}
    for a in assets:
        st = a.source_type
        if st not in source_risk:
            source_risk[st] = {'count': 0, 'vulnerable': 0, 'avg_qirs': 0, 'total_qirs': 0}
        source_risk[st]['count'] += 1
        if a.quantum_vulnerable:
            source_risk[st]['vulnerable'] += 1
        source_risk[st]['total_qirs'] += a.qirs
    for st in source_risk:
        source_risk[st]['avg_qirs'] = round(source_risk[st]['total_qirs'] / source_risk[st]['count'], 4) if source_risk[st]['count'] else 0
        del source_risk[st]['total_qirs']
    
    return {
        'risk_distribution': risk_bins,
        'scatter': scatter,
        'effort_distribution': dict(sorted(effort_dist.items())),
        'slack_summary': {'on_track': slack_positive, 'behind': slack_negative, 'critical': slack_critical},
        'key_sizes': dict(sorted(key_sizes.items())),
        'verdicts': verdicts,
        'axis_dominance': {'hndl_dominant': hndl_dominant, 'tnfl_dominant': tnfl_dominant, 'balanced': balanced},
        'source_risk': source_risk,
    }


@router.get('/announcements')
def get_announcements_list():
    from engine.announcements import get_active_announcements
    return get_active_announcements()

@router.post('/announcements/{announcement_id}/dismiss')
def dismiss_announcement_route(announcement_id: str):
    from engine.announcements import dismiss_announcement
    if not dismiss_announcement(announcement_id):
        raise HTTPException(status_code=404, detail='Announcement not found')
    return {'status': 'dismissed'}

# --------------------------------------------------------------------------
# Agent
#
# The agent is a governed write path into the estate, so its control surface is
# a first-class part of the API rather than a detail of the chat endpoint. See
# engine.agent_control for what each limit is for.
# --------------------------------------------------------------------------


class ChatRequest(BaseModel):
    """A full transcript, not a single message.

    The dashboard holds the conversation and replays it, so the server keeps no
    per-session state and a reload cannot desynchronise the two.
    """

    messages: List[Dict[str, Any]] = Field(default_factory=list)


class ControlSettingsRequest(BaseModel):
    mode: Optional[str] = None
    max_tool_calls_per_minute: Optional[int] = None
    max_iterations_per_turn: Optional[int] = None
    max_assets_per_action: Optional[int] = None
    turn_timeout_seconds: Optional[float] = None
    approval_ttl_seconds: Optional[float] = None


@router.post('/chat')
async def chat_endpoint(request: ChatRequest):
    """One agent turn: model call, tool calls, and any approval it queued."""
    from engine.agent import process_chat
    return await process_chat(request.messages)


@router.get("/ntro-mode")
def get_ntro_mode():
    """The three NTRO-mode facts as they stand: agent posture, model locality, offline guard."""
    from engine import ntro_mode, offline

    return {**ntro_mode.status(), "offline": offline.status()}


@router.get('/agent/status')
def get_agent_status():
    """Control mode, rate-limit budget and totals, plus the configured model.

    Identical in shape to the `control` block on every chat response - the
    dashboard swaps one for the other, so they cannot be allowed to drift.
    """
    from engine.agent import control_payload
    return control_payload()


@router.post('/agent/settings')
def update_agent_settings(request: ControlSettingsRequest):
    """Change the control limits at runtime."""
    from engine.agent_control import get_control
    control = get_control()
    changes = request.model_dump(exclude_none=True)
    try:
        control.update_settings(**changes)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    audit_chain.append("setting", "agent_settings", changes, actor="operator")
    return control.status()


@router.get('/agent/tools')
def get_agent_tools():
    """Every tool the agent has, and whether the current mode allows it."""
    from engine.agent import tool_catalogue
    return {'tools': tool_catalogue()}


@router.get('/agent/audit')
def get_agent_audit(limit: int = Query(100, ge=1, le=500)):
    """What the agent did, newest first. Includes refusals."""
    from engine.agent_control import get_control
    return {'entries': get_control().audit_log(limit=limit)}


# --------------------------------------------------------------------------
# API access keys
#
# These administer the /api/v1 integration surface. They live here rather than
# in integration.py deliberately: a key cannot be used to mint further keys, so
# issuing one stays an action taken in this dashboard by a human.
# --------------------------------------------------------------------------


class APIKeyRequest(BaseModel):
    name: str = Field(default='Integration key', max_length=60)
    # Write access is opt-in. A key that can only read cannot reach
    # migrate_asset even when the control plane would otherwise allow it.
    allow_write: bool = False


@router.get('/access-keys')
def list_access_keys():
    """Issued keys. Never returns key material - only a four-character hint."""
    from engine.api_keys import get_store
    store = get_store()
    return {
        'keys': store.list(),
        'active': store.active_count(),
        'note': (
            'Keys are held in memory and do not survive a restart, exactly like the '
            'language-model key. Production needs a persistent store with revocation '
            'that outlives the process.'
        ),
    }


@router.post('/access-keys')
def create_access_key(request: APIKeyRequest):
    """Issue a key. The plaintext is returned once and cannot be recovered."""
    from engine.api_keys import get_store
    scopes = ['read', 'write'] if request.allow_write else ['read']
    record, raw = get_store().issue(request.name, scopes)
    return {
        **record.to_dict(),
        'key': raw,
        'warning': 'Copy this now. Only a hash is stored, so it cannot be shown again.',
    }


@router.delete('/access-keys/{key_id}')
def revoke_access_key(key_id: str):
    """Revoke a key. Revoked rather than deleted, so the audit trail still
    resolves which key made a historical call."""
    from engine.api_keys import get_store
    if not get_store().revoke(key_id):
        raise HTTPException(status_code=404, detail='No such key, or already revoked.')
    return {'status': 'revoked', 'id': key_id}


@router.delete('/agent/audit')
def clear_agent_audit():
    from engine.agent_control import get_control
    get_control().reset()
    return {'status': 'cleared'}


@router.get('/agent/proposals')
def get_agent_proposals():
    """Changes the agent has proposed and a human has not yet ruled on."""
    from engine.agent_control import get_control
    return {'proposals': get_control().pending_proposals()}


@router.post('/agent/proposals/{proposal_id}/approve')
def approve_agent_proposal(proposal_id: str):
    """Apply a proposed change. This is the human half of approval mode."""
    from engine.agent import apply_proposal
    result = apply_proposal(proposal_id)
    if result.get('error'):
        raise HTTPException(status_code=409, detail=result['error'])
    return result


@router.post('/agent/proposals/{proposal_id}/reject')
def reject_agent_proposal(proposal_id: str):
    from engine.agent import reject_proposal
    result = reject_proposal(proposal_id)
    if result.get('error'):
        raise HTTPException(status_code=409, detail=result['error'])
    return result



# --------------------------------------------------------------------------
# Discovery surface
#
# The sensor layer, reported as data rather than assumed. Everything here reads
# the plugin registry (engine/discovery.py), so registering a new connector
# makes it appear on these endpoints with no change to this file.
# --------------------------------------------------------------------------


@router.get("/discovery/plugins")
def discovery_plugins():
    """Every registered sensor, its evidence grade, and whether it can run.

    Drives the radar view. Unconfigured enterprise connectors are included
    deliberately: a blind spot the operator can see is a planning input, and one
    they cannot see is a false sense of completeness. Also returns the five
    adapters' coverage contracts (proves / cannot_prove / requires) and honest
    file-dump vs live measurement status — never fabricated asset counts.
    """
    from engine.discovery import surface

    return surface()


@router.get("/adapters")
def list_adapters():
    """The five metadata adapters and what each can and cannot prove.

    Capability surface only: coverage_contract plus whether a vault file dump
    makes the adapter measurable. Does not claim live cloud or HSM connectivity.
    """
    from adapters import describe_adapters

    cards = describe_adapters()
    return {
        "adapters": cards,
        "ids": [c["id"] for c in cards],
    }


@router.get("/discovery/provenance")
def discovery_provenance():
    """The evidence grades themselves, with the reasoning for each.

    Exposed so the confidence attached to any asset can be traced to a stated
    rule rather than taken on trust.
    """
    from engine.plugins import PROVENANCE

    return {
        "grades": [
            {"key": key, **value}
            for key, value in sorted(
                PROVENANCE.items(), key=lambda kv: kv[1]["confidence"], reverse=True
            )
        ]
    }


class TreeScanRequest(BaseModel):
    """A request to scan a local directory for key material."""

    root: str = Field(..., description="Absolute or relative path to scan.")
    merge: bool = Field(
        default=False,
        description="Merge findings into the current inventory rather than only reporting them.",
    )


@router.post("/discovery/scan-tree")
def discovery_scan_tree(request: TreeScanRequest):
    """Scan a directory for key material and report what was found.

    Returns aggregates and fingerprint-level detail. The key material itself is
    never read back out: only a SHA-256 fingerprint is retained, which is what
    makes reuse detection possible without the scan creating a second copy of a
    credential.
    """
    from collectors.secret_scanner import reuse_clusters, scan_tree

    root = Path(request.root).expanduser()
    if not root.is_dir():
        raise HTTPException(status_code=400, detail=f"Not a directory: {request.root}")

    findings = scan_tree(root)
    clusters = reuse_clusters(findings)

    by_detection: Dict[str, int] = {}
    for finding in findings:
        method = finding.raw_details.get("detection", "unknown")
        by_detection[method] = by_detection.get(method, 0) + 1

    needs_review = sum(
        1 for f in findings if f.raw_details.get("requires_review")
    )

    merged = 0
    if request.merge and findings:
        process_findings(
            findings,
            0.0,
            kind="key_material",
            label=f"Key material scan ({len(findings)} findings)",
            org_persona=state.org_persona,
            merge=True,
        )
        merged = len(findings)

    return {
        "root": str(root),
        "found": len(findings),
        "by_detection": by_detection,
        "needs_review": needs_review,
        "reuse_clusters": clusters[:10],
        "reused_key_count": len(clusters),
        "merged_into_inventory": merged,
        "note": (
            "Only SHA-256 fingerprints are retained. No key material is stored, "
            "logged, or returned by this endpoint."
        ),
    }


# --------------------------------------------------------------------------
# Enterprise fit and post-quantum-era threats
#
# Two questions the rest of the product cannot answer: "is this inventory the
# right shape for the kind of organisation we are", and "what is still wrong
# after we finish migrating".
# --------------------------------------------------------------------------


@router.get("/profiles")
def enterprise_profiles():
    """The enterprise profiles this engine can be fitted to."""
    from engine.profiles import list_profiles

    return {"profiles": list_profiles(), "default": "payments"}


@router.get("/profiles/{profile_key}/fit")
def enterprise_fit(profile_key: str):
    """How well the current deployment fits one kind of enterprise.

    Reports required-sensor coverage and expected-but-absent asset classes, so
    an incomplete inventory is described as incomplete rather than presented as
    a finished one.
    """
    from engine.discovery import register_builtins
    from engine.profiles import PROFILES, fit_report

    if profile_key not in PROFILES:
        raise HTTPException(
            status_code=404,
            detail=f"No such profile: {profile_key}. Available: {', '.join(PROFILES)}",
        )

    registry = register_builtins()
    plugin_states = {p["id"]: p["available"] for p in registry.describe_all()}
    return fit_report(profile_key, plugin_states, state.assets or [])


@router.get("/pqc-threats")
def pqc_threat_register():
    """Risks that exist during and after a post-quantum migration."""
    from engine.pqc_threats import register

    return {"threats": register()}


@router.get("/pqc-threats/assessment")
def pqc_threat_assessment():
    """Which post-quantum-era threats apply to the loaded estate."""
    from engine.pqc_threats import assess

    return assess(state.assets or [])


# --------------------------------------------------------------------------
# The engine
#
# The scan pipeline (engine/core/scan_pipeline.py), exposed so the UI can
# render the stages running rather than a spinner. Every figure returned here
# carries the trace that produced it.
# --------------------------------------------------------------------------


_engine_run = {"run": None}


def _current_run(detail_for=None):
    from engine.core import scan_pipeline
    from engine.core.policy import get_current

    run = scan_pipeline.run(state.assets or [], detail_for=detail_for, policy=get_current())
    _engine_run["run"] = run
    return run


@router.post("/engine/run")
def engine_run():
    """Run the scan pipeline once and report what each stage did."""
    from engine.core.scan_pipeline import STAGE_META, STAGES

    if not state.assets:
        raise HTTPException(
            status_code=409,
            detail="No estate loaded. Run a scan or load the demo estate first.",
        )

    run = _current_run()
    grouped = run.trace.by_stage()

    return {
        "run_id": run.trace.run_id,
        "stats": run.stats,
        "checks": run.checks,
        "checks_passed": run.checks_passed,
        "manifest": run.manifest,
        "quarantined": run.quarantined[:25],
        "stages": [
            {
                "key": stage,
                **STAGE_META[stage],
                "events": grouped.get(stage, []),
                "microseconds": run.trace.stage_timings.get(stage, 0),
            }
            for stage in STAGES
        ],
        "trace": run.trace.summary(),
    }


@router.get("/engine/state")
def engine_state():
    """The pipeline's current output: the ranked estate and what to verify first."""
    run = _engine_run["run"] or (_current_run() if state.assets else None)
    if run is None:
        raise HTTPException(status_code=409, detail="No estate loaded.")

    return {
        "run_id": run.trace.run_id,
        "stats": run.stats,
        "ranked": run.ranked[:200],
        "flagged": run.flagged[:50],
        "checks": run.checks,
        "checks_passed": run.checks_passed,
    }


@router.get("/engine/asset/{asset_id}")
def engine_asset_trace(asset_id: str):
    """One asset's full journey through every pipeline stage.

    This is the drill-down that makes the engine auditable: every number with
    the observation and the rule that produced it.
    """
    if not state.assets:
        raise HTTPException(status_code=409, detail="No estate loaded.")

    run = _current_run(detail_for={asset_id})
    if asset_id not in run.corroboration:
        raise HTTPException(status_code=404, detail=f"No such asset: {asset_id}")

    from engine import mosca
    from engine.core import traversal

    asset = next((a for a in state.assets if a.id == asset_id), None)
    scored = next((r for r in run.ranked if r["id"] == asset_id), None)
    evidence = run.corroboration[asset_id]
    mosca_reading = mosca.assess(asset) if asset is not None else None

    return {
        "asset_id": asset_id,
        "name": getattr(asset, "name", asset_id),
        "asset_class": getattr(asset, "asset_class", None),
        # The stage-by-stage journey, each step carrying the formula that was
        # applied and the values substituted into it. This is what replaced the
        # block diagram: an operator asks about one asset, not about the shape
        # of the machine.
        "traversal": traversal.build(
            asset, evidence, scored, mosca_reading,
        ) if asset is not None else [],
        "observations": evidence["readings"],
        "corroboration": evidence,
        "mosca": mosca_reading,
        "scored": scored,
        "trace": run.trace.for_subject(asset_id),
    }


# --------------------------------------------------------------------------
# Sector packs - the plug in / plug out surface
# --------------------------------------------------------------------------


@router.get("/packs")
def list_packs():
    """Every registered pack and whether it is currently plugged in."""
    from engine.packs import REGISTRY

    packs = REGISTRY.describe()
    return {
        "packs": packs,
        "enabled": sum(1 for p in packs if p["enabled"]),
        "total": len(packs),
        "note": (
            "The engine computes identically for every sector. Packs supply what "
            "is said about the result - controls, evidence, dates and language."
        ),
    }


@router.get("/packs/resolved/{sector}")
def resolved_pack_content(sector: str):
    """The merged content that applies to one sector right now."""
    from engine.packs import REGISTRY

    return REGISTRY.resolved(sector)


class PackToggle(BaseModel):
    enabled: bool = Field(..., description="Plug the pack in, or unplug it.")


@router.post("/packs/{pack_id}/toggle")
def toggle_pack(pack_id: str, request: PackToggle):
    """Plug a pack in or out at runtime.

    Refusing to unplug the baseline is deliberate: with no pack at all the
    product would have nothing to say, which is a broken state rather than an
    agnostic one.
    """
    from engine.packs import PACKS, REGISTRY

    if pack_id not in PACKS:
        raise HTTPException(
            status_code=404,
            detail=f"No such pack: {pack_id}. Available: {', '.join(sorted(PACKS))}",
        )

    ok = REGISTRY.enable(pack_id) if request.enabled else REGISTRY.disable(pack_id)
    if not ok and not request.enabled:
        raise HTTPException(
            status_code=409,
            detail=(
                "The baseline pack cannot be unplugged. It carries the "
                "obligations that bind every sector, so removing it would leave "
                "the product with nothing to say rather than less to say."
            ),
        )

    return {
        "pack_id": pack_id,
        "enabled": REGISTRY.is_enabled(pack_id),
        "packs_enabled": sum(1 for p in REGISTRY.describe() if p["enabled"]),
    }


@router.get("/engine/migration-plan")
def migration_plan():
    """The formal migration model: clusters, order, depth.

    Implements Loebenberger et al., arXiv:2408.05997. Answers the question ranking
    cannot: in what order can these move, and what must move together?
    """
    from engine.core.migration_graph import analyse

    assets = _require_scan()
    graph = build_graph(assets)
    names = {n["id"]: n["name"] for n in graph["nodes"]}
    return analyse(
        [n["id"] for n in graph["nodes"]],
        [(e["source"], e["target"]) for e in graph["edges"]],
        names,
    )


@router.get("/agents/pool")
def agent_pool_status():
    """The agent key pool: capacity, health, and what each task is for."""
    from engine.core.agent_tasks import TASKS
    from engine.core.agents import POOL, PROVIDERS

    from engine.core.model_health import REGISTRY as MODELS

    return {
        "capacity": POOL.capacity(),
        "keys": [k.to_dict() for k in POOL.all()],
        # Which models actually answer, measured rather than advertised.
        "model_health": MODELS.report(),
        "providers": [
            {"id": key, **{k: v for k, v in preset.items() if k != "base_url"}}
            for key, preset in PROVIDERS.items()
        ],
        "tasks": [{"id": key, **meta} for key, meta in TASKS.items()],
        "note": (
            "A model's answer enters the engine as a graded observation, never "
            "as a number. It carries the weakest provenance grade and can be "
            "outvoted by any stronger sensor."
        ),
    }


class AgentKeyInput(BaseModel):
    provider: str
    api_key: str
    model: str = ""
    base_url: str = ""


@router.post("/agents/keys")
def add_agent_key(request: AgentKeyInput):
    """Add a credential to the pool. The secret is held in memory only."""
    from engine.core.agents import POOL, PROVIDERS

    if request.provider not in PROVIDERS:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown provider. One of: {', '.join(PROVIDERS)}",
        )
    if not request.api_key.strip():
        raise HTTPException(status_code=400, detail="An API key is required.")

    key = POOL.add(
        request.provider, request.api_key.strip(),
        model=request.model, base_url=request.base_url,
    )
    return {"key": key.to_dict(), "capacity": POOL.capacity()}


@router.delete("/agents/keys/{key_id}")
def remove_agent_key(key_id: str):
    from engine.core.agents import POOL

    if not POOL.remove(key_id):
        raise HTTPException(status_code=404, detail=f"No such key: {key_id}")
    return {"removed": key_id, "capacity": POOL.capacity()}


# --------------------------------------------------------------------------
# Engine policy as code (W3a)
#
# The organisation supplies parameters; the engine stays a skeleton. Preview
# always runs before save so an operator can see rank moves and invariant
# status under a proposed document.
# --------------------------------------------------------------------------


@router.get("/engine/policy")
def get_engine_policy():
    """The policy document currently governing the engine."""
    from engine.core.policy import get_current

    policy = get_current()
    return {
        "policy": policy.to_dict(),
        "preset": policy.preset,
    }


@router.put("/engine/policy")
def put_engine_policy(body: dict):
    """Validate and save a policy document. Prefer previewing first."""
    from engine.core.policy import set_current, validate_policy

    payload = body.get("policy", body) if isinstance(body, dict) else body
    try:
        validated = validate_policy(payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    saved = set_current(validated)
    # Drop any cached run so the next engine cycle uses the new document.
    _engine_run["run"] = None
    audit_chain.append("setting", "engine_policy", {"preset": saved.preset}, actor="operator")
    return {
        "policy": saved.to_dict(),
        "preset": saved.preset,
        "saved": True,
    }


@router.post("/engine/policy/preview")
def preview_engine_policy(body: dict):
    """Run the estate under a proposed policy without saving it.

    Returns rank moves and check status against the current policy. Saving is
    refused in the UI until this has been called.
    """
    from engine.core import scan_pipeline
    from engine.core.policy import compare_rankings, get_current, validate_policy

    if not state.assets:
        raise HTTPException(
            status_code=409,
            detail="No estate loaded. Run a scan or load the demo estate first.",
        )

    payload = body.get("policy", body) if isinstance(body, dict) else body
    try:
        proposed = validate_policy(payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    current_policy = get_current()
    current_run = scan_pipeline.run(state.assets, policy=current_policy)
    proposed_run = scan_pipeline.run(state.assets, policy=proposed)
    diff = compare_rankings(current_run.ranked, proposed_run.ranked)

    def _check_summary(run):
        return {
            "checks_passed": run.checks_passed,
            "passed": sum(1 for c in run.checks if c["passed"]),
            "failed": sum(1 for c in run.checks if not c["passed"]),
            "checks": run.checks,
        }

    return {
        "proposed": proposed.to_dict(),
        "current": current_policy.to_dict(),
        "rank_moves": diff["rank_moves"],
        "moved_count": diff["moved_count"],
        "entered_ranking": diff["entered_ranking"],
        "left_ranking": diff["left_ranking"],
        "flagged": {
            "current": current_run.stats["flagged"],
            "proposed": proposed_run.stats["flagged"],
        },
        "checks": {
            "current": _check_summary(current_run),
            "proposed": _check_summary(proposed_run),
        },
        "stats": {
            "current": current_run.stats,
            "proposed": proposed_run.stats,
        },
    }


@router.get("/engine/policy/presets")
def list_engine_policy_presets(sector: str | None = None):
    """Named presets, optionally including a sector overlay from packs."""
    from engine.core.policy import list_presets, sector_defaults

    presets = list_presets()
    if sector:
        sector_pol = sector_defaults(sector)
        presets.append({
            "id": f"sector:{sector}",
            "name": sector_pol.name,
            "description": sector_pol.description,
            "policy": sector_pol.to_dict(),
        })
    return {"presets": presets}


# --------------------------------------------------------------------------
# Notifications — derived from live estate / engine / pool state only.
# Nothing is fabricated here; an empty estate with no feed yields [].
# --------------------------------------------------------------------------


def _notif_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _notif_item(
    *,
    nid: str,
    source: str,
    severity: str,
    title: str,
    body: str,
    deep_link: str,
    occurred_at: str | None = None,
) -> dict:
    return {
        "id": nid,
        "source": source,
        "severity": severity if severity in ("critical", "warning", "info") else "info",
        "title": title,
        "body": body,
        "occurred_at": occurred_at or _notif_now(),
        "deep_link": deep_link,
    }


@router.get("/notifications")
def get_notifications():
    """Operator notifications derived from current product state.

    Sources checked (only when they have something real to say):
      1. Certificate expiry bands on loaded assets
      2. Assets with negative statutory slack
      3. Last pipeline run with a failing output check (cached run only)
      4. Discovery blind spots / required-but-inactive sensors
      5. Trust partners blocking rotation
      6. Model health circuit-open / retired models
      7. Undismissed announcements from the feed
    """
    items: list[dict] = []
    assets = state.assets or []
    now = _notif_now()

    # 1. Certificates crossing an expiry band
    expiry_hits = [
        a for a in assets
        if getattr(a, "expiry_band", "none") in ("expired", "critical", "warning")
    ]
    if expiry_hits:
        expired = sum(1 for a in expiry_hits if a.expiry_band == "expired")
        critical = sum(1 for a in expiry_hits if a.expiry_band == "critical")
        warning = sum(1 for a in expiry_hits if a.expiry_band == "warning")
        severity = "critical" if (expired or critical) else "warning"
        parts = []
        if expired:
            parts.append(f"{expired} expired")
        if critical:
            parts.append(f"{critical} critical")
        if warning:
            parts.append(f"{warning} warning")
        items.append(_notif_item(
            nid="expiry-band",
            source="estate",
            severity=severity,
            title=f"{len(expiry_hits)} certificate(s) crossing an expiry band",
            body=", ".join(parts) + ". Open Assets to prioritise renewal.",
            deep_link="assets",
            occurred_at=now,
        ))

    # 2. Negative slack
    behind = [a for a in assets if getattr(a, "slack_months", 0) < 0]
    if behind:
        worst = min(behind, key=lambda a: a.slack_months)
        items.append(_notif_item(
            nid="negative-slack",
            source="estate",
            severity="critical",
            title=f"{len(behind)} asset(s) behind statutory deadline",
            body=(
                f"Worst slack is {worst.slack_months:.1f} months on "
                f"{getattr(worst, 'name', worst.id)}. Roadmap ranks these first."
            ),
            deep_link="roadmap",
            occurred_at=now,
        ))

    # 3. Last pipeline run had a failing output check (cached only — no new run)
    run = _engine_run.get("run")
    if run is not None and not getattr(run, "checks_passed", True):
        failed = [c for c in (run.checks or []) if not c.get("passed")]
        names = ", ".join(c.get("key", "?") for c in failed[:3])
        items.append(_notif_item(
            nid=f"pipeline-check-failed-{getattr(getattr(run, 'trace', None), 'run_id', 'last')}",
            source="engine",
            severity="critical",
            title="Pipeline output check failed",
            body=(
                f"{len(failed)} output check(s) failed on the last run"
                + (f": {names}" if names else "")
                + ". The ranking is still shown; open Engine to inspect."
            ),
            deep_link="engine",
            occurred_at=now,
        ))

    # 4. Blind spots / required but inactive sensors
    try:
        from engine.discovery import register_builtins, surface
        from engine.profiles import PROFILES, fit_report

        coverage = surface().get("coverage") or {}
        blind = coverage.get("blind_spots") or []
        if blind:
            sample = ", ".join(b.get("name") or b.get("id", "?") for b in blind[:3])
            more = f" (+{len(blind) - 3} more)" if len(blind) > 3 else ""
            items.append(_notif_item(
                nid="discovery-blind-spots",
                source="discovery",
                severity="warning",
                title=f"{len(blind)} sensor blind spot(s)",
                body=f"{sample}{more}. Configure connectors under Scanner / Settings.",
                deep_link="settings",
                occurred_at=now,
            ))

        profile_key = (state.org_persona or "").strip().lower()
        if profile_key not in PROFILES:
            profile_key = "payments"
        registry = register_builtins()
        plugin_states = {p["id"]: p["available"] for p in registry.describe_all()}
        fit = fit_report(profile_key, plugin_states, assets)
        missing = fit.get("missing_required_sensors") or []
        if missing:
            items.append(_notif_item(
                nid=f"fit-missing-{profile_key}",
                source="enterprise-fit",
                severity="warning",
                title=f"{len(missing)} required sensor(s) inactive",
                body=(
                    f"For the {profile_key} profile: {', '.join(missing[:5])}. "
                    "Audit readiness is blocked until these are active."
                ),
                deep_link="settings",
                occurred_at=now,
            ))
    except Exception:
        pass

    # 6. Model health retired / circuit open
    try:
        from engine.core.model_health import REGISTRY as MODELS

        report = MODELS.report()
        retired = [m for m in (report.get("models") or []) if not m.get("available")]
        if retired:
            sample = ", ".join(m.get("model", "?") for m in retired[:3])
            items.append(_notif_item(
                nid="model-health-retired",
                source="agents",
                severity="warning",
                title=f"{len(retired)} model(s) retired from rotation",
                body=(
                    f"{sample}. Reliability circuit is open — check AI providers "
                    "in Settings."
                ),
                deep_link="settings",
                occurred_at=now,
            ))
    except Exception:
        pass

    # 7. Undismissed announcements
    try:
        from engine.announcements import get_active_announcements

        for ann in get_active_announcements():
            date = getattr(ann, "date", None) or now
            if len(date) == 10 and date[4] == "-" and date[7] == "-":
                occurred = f"{date}T00:00:00Z"
            else:
                occurred = date if "T" in date else now
            items.append(_notif_item(
                nid=f"announcement-{ann.id}",
                source=ann.source or "announcements",
                severity=ann.severity,
                title=ann.title,
                body=ann.body,
                deep_link="dashboard",
                occurred_at=occurred,
            ))
    except Exception:
        pass

    severity_order = {"critical": 0, "warning": 1, "info": 2}
    items.sort(
        key=lambda i: (
            severity_order.get(i["severity"], 3),
            i.get("occurred_at") or "",
        ),
    )

    return {"items": items}


# ---------------------------------------------------------------------------
# Key vault — the systems of record for the keys that actually matter
# ---------------------------------------------------------------------------


@router.post("/scan/vault", response_model=ScanResult)
def run_vault_scan(
    org_persona: str = Query("Banking"),
    merge: bool = Query(False),
    vault_root: str | None = Query(None),
):
    """Ingest key-manager metadata: HSM slots, KMIP objects, cloud KMS.

    `merge=true` folds the vault into the estate already loaded, which is the
    realistic path — an organisation has TLS endpoints *and* an HSM, and the
    interesting assets are the ones only the HSM knows about.
    """
    from collectors import vault_collector

    start = datetime.datetime.now()
    findings, errors = vault_collector.scan_vault(vault_root)
    duration = (datetime.datetime.now() - start).total_seconds()

    if not findings:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "No key-manager metadata was found.",
                "remedy": (
                    "Generate the demo vault with `python demo/vault/make_vault.py`, "
                    "or point vault_root at a PKCS#11/KMIP/cloud-KMS export."
                ),
                "errors": errors,
            },
        )

    result = process_findings(
        findings, duration, kind="vault", label="Key manager metadata",
        org_persona=org_persona, merge=merge,
    )
    # Unmeasured sources travel with the result. An estate assembled from four
    # of five sources is not the same claim as one assembled from five.
    result.warnings = errors
    return result


@router.get("/vault/summary")
def get_vault_summary(vault_root: str | None = Query(None)):
    """What the vault holds and what it cannot see."""
    from collectors import vault_collector

    return vault_collector.vault_summary(vault_root)


# ---------------------------------------------------------------------------
# Model probing — finding out which free models actually work
#
# A gateway advertising 514 models is not offering 514 usable ones, and the pool
# used to discover that during the task that needed one. These routes move the
# discovery earlier: a bounded, deliberate test run whose results land in the
# same health registry the scheduler already reads.
#
# Both routes are declared `def` rather than `async def` on purpose. The probe
# is blocking httpx across a small thread pool, and FastAPI runs a sync route in
# its own worker thread — so a probe run cannot stall the event loop that is
# serving the dashboard and the agent's SSE stream at the same time.
# ---------------------------------------------------------------------------


class ProbeRequest(BaseModel):
    """What to probe. Every field is optional; the defaults are the safe run."""

    #: Name models explicitly to probe exactly those. Left empty, the run uses
    #: the gateway's `auto/*` routes plus a small explicit list.
    models: list[str] = []
    base_url: str = ""
    #: Hard-capped server-side. A caller cannot talk the run into 514 requests.
    limit: int = 0
    concurrency: int = 0


@router.post("/agents/probe")
def probe_agent_models(request: ProbeRequest):
    """Run a probe and report what was measured.

    This spends real requests against a real quota, which is why it is a POST
    and why nothing triggers it automatically. Two tiny calls per model: one
    plain completion, and — only if that answered — one with a tool attached.
    """
    from engine.core.agents import POOL, PROVIDERS, probe_models

    base_url = request.base_url.strip() or PROVIDERS["omniroute"]["base_url"]

    # Reuse a pooled credential for this endpoint if the operator added one.
    # A self-hosted gateway needs none, and the probe omits the header entirely
    # rather than sending an empty bearer token, which httpx rejects outright.
    secret = POOL.secret_for(base_url)

    try:
        result = probe_models(
            request.models or None,
            base_url=base_url,
            secret=secret,
            limit=request.limit or None,
            concurrency=request.concurrency or None,
        )
    except Exception as exc:  # noqa: BLE001
        # A probe that cannot run reports why. It must never fall back to
        # returning a cached or invented verdict — that is precisely the
        # fabrication this feature exists to prevent.
        raise HTTPException(
            status_code=502,
            detail={
                "error": f"The probe could not run: {type(exc).__name__}: {exc}",
                "remedy": (
                    f"Check that a gateway is reachable at {base_url}. For "
                    f"OmniRoute: curl {base_url}/models"
                ),
            },
        ) from exc

    return result


@router.get("/agents/probe")
def get_agent_probe_results(base_url: str | None = Query(None)):
    """What previous probes established. Sends no requests and spends nothing.

    Separate from the POST so the dashboard can render probe state on load
    without quietly burning quota every time somebody opens the page.
    """
    from engine.core.agents import (
        PROBE_DEFAULT_LIMIT,
        PROVIDERS,
        EXPLICIT_PROBE_MODELS,
    )
    from engine.llm_bridge import MAX_FAILOVER_MODELS
    from engine.core.model_health import REGISTRY as MODELS

    endpoint = (base_url or PROVIDERS["omniroute"]["base_url"]).rstrip("/")
    report = MODELS.probe_report(endpoint)
    return {
        **report,
        "default_limit": PROBE_DEFAULT_LIMIT,
        "explicit_models": list(EXPLICIT_PROBE_MODELS),
        # What the agent loop would actually fall through to. Two things make
        # this narrower than the list of working models, and both are shown
        # rather than described: the loop needs tool calls, so a text-only model
        # is not offered to it at all, and the chain is capped, because a turn
        # has its own wall-clock budget and a chain long enough to exhaust it
        # fails just as surely as no chain — only slower and dearer.
        "failover_chain": MODELS.known_good(
            endpoint=endpoint, require_tools=True,
        )[:MAX_FAILOVER_MODELS],
        "failover_limit": MAX_FAILOVER_MODELS,
    }
