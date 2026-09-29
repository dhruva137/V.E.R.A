from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class RawCryptoFinding(BaseModel):
    """What a collector emits. No scoring, no interpretation."""

    id: str
    source_type: str  # tls | keystore | config | source
    source_location: str
    # Set by collectors to select a QIRS policy profile (see engine.qirs.PROFILES).
    asset_class: Optional[str] = None
    algorithm: Optional[str] = None
    key_size: Optional[int] = None
    protocol: Optional[str] = None
    cipher_suite: Optional[str] = None
    key_exchange: Optional[str] = None
    signature_algorithm: Optional[str] = None
    cert_subject: Optional[str] = None
    cert_issuer: Optional[str] = None
    cert_validity_start: Optional[str] = None
    cert_validity_end: Optional[str] = None
    cert_serial: Optional[str] = None
    usage: Optional[str] = None
    # Free-form labels used for persona escalation and grouping in the UI.
    tags: List[str] = Field(default_factory=list)
    owner: Optional[str] = None
    environment: Optional[str] = None  # production | staging | dr
    raw_details: Dict[str, Any] = Field(default_factory=dict)


class CryptoAsset(RawCryptoFinding):
    """A finding after classification, scoring and regulatory mapping."""

    name: str

    # --- Classification (engine.taxonomy) ---
    verdict: str = "unknown"  # shor | grover | classical | pqc | unknown
    quantum_vulnerable: bool = False
    classically_broken: bool = False
    grover_weakened: bool = False
    vulnerability_reason: str = ""
    primitive: str = "unknown"
    classical_bits: Optional[int] = None
    nist_quantum_level: int = 0
    pqc_replacement: Optional[str] = None
    curve: Optional[str] = None
    oid: Optional[str] = None
    suite_breakdown: Optional[Dict[str, Any]] = None
    classification_components: List[Dict[str, Any]] = Field(default_factory=list)

    # --- QIRS policy inputs (engine.qirs.PolicyProfile) ---
    x_c: float = 0.0
    x_i: float = 0.0
    y: float = 0.0
    s: float = 0.0
    e: float = 0.0
    c: float = 0.0
    profile_label: str = ""
    profile_rationale: str = ""

    # --- Scores ---
    h_score: float = 0.0
    t_score: float = 0.0
    qirs: float = 0.0
    qirs_low: float = 0.0
    qirs_high: float = 0.0

    # --- Regulatory (engine.regulatory) ---
    persona: str = "General Enterprise"
    persona_source: str = ""
    binding_phase: str = "full"
    binding_phase_reason: str = ""
    statutory_deadline_year: int = 2033
    slack_months: float = 0.0

    # --- Operability (engine.expiry, engine.agility) ---
    #
    # Neither is a risk score. Expiry is the deadline that arrives before the
    # statutory one; agility is whether anything can be done about the asset
    # today. Both are precomputed during scoring so the inventory and dashboard
    # read them without recomputing per request.
    expiry_days: Optional[int] = None
    expiry_band: str = "none"       # expired | critical | warning | ok | none
    agility_key: str = "coordinated"
    agility_label: str = "Coordinated change"
    agility_actionable: bool = True

    # --- Mosca (engine.mosca) ---
    # Category on the asset's dominant axis: certain | likely | possible | clear
    # | not_applicable. The margin is (horizon - Z) under the median reading, in
    # years; positive means the asset is exposed before migration can finish.
    mosca_category: str = ""
    mosca_axis: str = ""
    mosca_margin_years: Optional[float] = None

    # --- Priority ---
    risk_level: str = "low"
    priority_rank: int = 0

    # Set by the hybrid harness when this asset has been migrated in-place.
    migrated: bool = False
    migrated_from: Optional[str] = None


class DashboardSummary(BaseModel):
    total_assets: int
    quantum_vulnerable: int
    quantum_safe: int
    classically_broken: int
    grover_weakened: int
    by_algorithm: Dict[str, int]
    by_verdict: Dict[str, int]
    by_risk_level: Dict[str, int]
    by_persona: Dict[str, int]
    by_source_type: Dict[str, int]
    by_asset_class: Dict[str, int]
    avg_hndl: float
    avg_tnfl: float
    avg_qirs: float
    max_qirs: float
    negative_slack_count: int
    worst_slack_months: float
    top_risk_asset_id: Optional[str] = None
    scan_timestamp: str
    scan_id: Optional[str] = None
    org_persona: str = "Banking"


class HeatmapCell(BaseModel):
    hndl_bucket: str
    tnfl_bucket: str
    hndl_index: int
    tnfl_index: int
    count: int
    asset_ids: List[str]
    avg_qirs: float
    top_asset_name: Optional[str] = None
    # Upper bound of both axes for this scan. Neither axis can reach 1.0 at
    # realistic horizons, so the grid is scaled to what is achievable and the
    # scale is reported rather than assumed.
    axis_max: float = 1.0


class RoadmapItem(BaseModel):
    asset_id: str
    asset_name: str
    algorithm: str
    persona: str
    asset_class: Optional[str] = None
    # Fractional years so the Gantt can render sub-year migrations honestly.
    start_year: float
    end_year: float
    migration_start: str
    migration_end: str
    deadline_year: int
    slack_months: float
    phase: str
    risk_level: str
    qirs: float
    overruns_deadline: bool


class ScanRequest(BaseModel):
    targets: List[str] = Field(default_factory=list)
    # Optional: the previous version made this required, so the front end's
    # {targets: [...]} body produced a 422 and live scanning never worked.
    scan_type: str = "tls"
    org_persona: str = "Banking"
    # Add results to the current inventory rather than replacing it, so a live
    # endpoint scan can sit alongside an already-loaded estate.
    merge: bool = False


class ScanResult(BaseModel):
    scan_id: str
    status: str
    message: str
    assets_found: int
    quantum_vulnerable: int
    classically_broken: int
    negative_slack_count: int
    cbom_id: str
    cbom_valid: bool
    scan_duration_seconds: float
    targets_attempted: int = 0
    targets_reachable: int = 0
    unreachable: List[Dict[str, str]] = Field(default_factory=list)
    # Sources that were asked for and did not report. An estate assembled from
    # four of five sources is a different claim from one assembled from five,
    # so the shortfall travels with the result rather than being inferred from
    # a smaller number.
    warnings: List[str] = Field(default_factory=list)


class ScanSummary(BaseModel):
    """One row of scan history."""

    scan_id: str
    timestamp: str
    kind: str
    label: str
    total_assets: int
    quantum_vulnerable: int
    avg_qirs: float
    negative_slack_count: int


class MigrationRequest(BaseModel):
    """M8 hybrid harness: migrate a subset of the estate in place."""

    # Exact asset id wins over target substring — a single-asset preview picks one row.
    asset_id: Optional[str] = None
    # Substring matched against source_location; empty means the whole estate.
    target: str = ""
    # Which asset classes to migrate. Empty means every vulnerable asset.
    asset_classes: List[str] = Field(default_factory=list)
    strategy: str = "hybrid"  # hybrid | pqc_only
