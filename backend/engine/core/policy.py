"""Engine policy as code — the configurable half of the risk engine.

The engine is a skeleton; this document supplies the parameters an organisation
actually owns: the six QIRS inputs, composite weights, risk bands, the
confidence below which a finding is flagged for verification, provenance
confidences, and which survival curve reading to use. Named presets and optional sector overlays from
``engine/packs.py`` let an operator start from something auditable rather than
inventing numbers.
"""

from __future__ import annotations

import copy
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

DATA_DIR = Path(__file__).resolve().parents[2] / "data"
POLICY_FILE = DATA_DIR / "engine_policy.json"

SurvivalReading = Literal["optimistic", "median", "pessimistic"]
SURVIVAL_READINGS = ("optimistic", "median", "pessimistic")

# Balanced == shipped behaviour, so threading policy through the scan pipeline
# does not move existing rankings.
_BALANCED_PROVENANCE = {
    "runtime_observed": 0.98,
    "artifact_parsed": 0.90,
    "declared": 0.85,
    "config_parsed": 0.70,
    "imported": 0.65,
    "static_analysis": 0.55,
    "heuristic": 0.35,
    "inferred": 0.25,
}

_BALANCED_RISK_BANDS = [
    {"threshold": 0.30, "level": "high"},
    {"threshold": 0.18, "level": "medium"},
    {"threshold": 0.08, "level": "low"},
]

_GENERIC_INPUTS = {
    "x_c": 7.0, "x_i": 5.0, "y": 1.5, "s": 0.7, "e": 0.4, "c": 0.6,
}


@dataclass
class EnginePolicy:
    """A versioned, exportable description of how the engine should compute."""

    version: str = "1.0.0"
    name: str = "balanced"
    description: str = (
        "Neutral defaults matching the shipped engine constants. Equal axis "
        "weights, median survival reading, flag below 0.50 confidence."
    )
    w_H: float = 0.5
    w_T: float = 0.5
    risk_bands: list[dict[str, Any]] = field(
        default_factory=lambda: copy.deepcopy(_BALANCED_RISK_BANDS)
    )
    #: Corroborated confidence below which an asset is flagged for verification.
    #: A flag never removes an asset from the ranking.
    flag_threshold: float = 0.50
    provenance_confidences: dict[str, float] = field(
        default_factory=lambda: dict(_BALANCED_PROVENANCE)
    )
    survival_curve_reading: SurvivalReading = "median"
    input_defaults: dict[str, float] = field(
        default_factory=lambda: dict(_GENERIC_INPUTS)
    )
    asset_class_inputs: dict[str, dict[str, float]] = field(default_factory=dict)
    preset: str | None = "balanced"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EnginePolicy:
        """Build a policy from a JSON/YAML-ish mapping after validation."""
        return validate_policy(data)


def _profiles_as_inputs() -> dict[str, dict[str, float]]:
    """Six-input overrides keyed by asset class, from ``engine.qirs.PROFILES``."""
    try:
        from engine.qirs import PROFILES
    except Exception:
        return {}
    out: dict[str, dict[str, float]] = {}
    for key, profile in PROFILES.items():
        out[key] = {
            "x_c": float(profile.x_c),
            "x_i": float(profile.x_i),
            "y": float(profile.y),
            "s": float(profile.s),
            "e": float(profile.e),
            "c": float(profile.c),
        }
    return out


def balanced_policy() -> EnginePolicy:
    """Ship defaults — identical to today's hardcoded module constants."""
    return EnginePolicy(
        version="1.0.0",
        name="balanced",
        description=(
            "Neutral defaults matching the shipped engine constants. Equal axis "
            "weights, median survival reading, flag below 0.50 confidence."
        ),
        w_H=0.5,
        w_T=0.5,
        risk_bands=copy.deepcopy(_BALANCED_RISK_BANDS),
        flag_threshold=0.50,
        provenance_confidences=dict(_BALANCED_PROVENANCE),
        survival_curve_reading="median",
        input_defaults=dict(_GENERIC_INPUTS),
        asset_class_inputs=_profiles_as_inputs(),
        preset="balanced",
    )


def conservative_policy() -> EnginePolicy:
    """Cautious posture: earlier CRQC reading, stricter flag, tighter bands."""
    base = balanced_policy()
    base.version = "1.0.0"
    base.name = "conservative"
    base.preset = "conservative"
    base.description = (
        "Assumes an earlier CRQC (pessimistic survival), weights confidentiality "
        "more heavily, and flags weakly evidenced assets sooner."
    )
    base.w_H = 0.65
    base.w_T = 0.35
    base.survival_curve_reading = "pessimistic"
    base.flag_threshold = 0.65
    base.risk_bands = [
        {"threshold": 0.22, "level": "high"},
        {"threshold": 0.12, "level": "medium"},
        {"threshold": 0.05, "level": "low"},
    ]
    base.provenance_confidences = {
        key: round(max(0.15, conf * 0.92), 4)
        for key, conf in _BALANCED_PROVENANCE.items()
    }
    return base


def aggressive_policy() -> EnginePolicy:
    """Optimistic posture: later CRQC reading, looser flag, wider bands."""
    base = balanced_policy()
    base.version = "1.0.0"
    base.name = "aggressive"
    base.preset = "aggressive"
    base.description = (
        "Assumes a later CRQC (optimistic survival), weights integrity more "
        "heavily, and flags only very weakly evidenced assets."
    )
    base.w_H = 0.4
    base.w_T = 0.6
    base.survival_curve_reading = "optimistic"
    base.flag_threshold = 0.35
    base.risk_bands = [
        {"threshold": 0.38, "level": "high"},
        {"threshold": 0.24, "level": "medium"},
        {"threshold": 0.12, "level": "low"},
    ]
    return base


PRESETS: dict[str, callable] = {
    "conservative": conservative_policy,
    "balanced": balanced_policy,
    "aggressive": aggressive_policy,
}


def preset(name: str) -> EnginePolicy:
    key = (name or "").strip().lower()
    if key not in PRESETS:
        raise ValueError(
            f"Unknown preset {name!r}. One of: {', '.join(sorted(PRESETS))}."
        )
    return PRESETS[key]()


def list_presets() -> list[dict[str, Any]]:
    return [
        {
            "id": key,
            "name": pol.name,
            "description": pol.description,
            "policy": pol.to_dict(),
        }
        for key, factory in PRESETS.items()
        for pol in (factory(),)
    ]


# Sector overlays applied on top of balanced when a pack is available.
_SECTOR_OVERLAYS: dict[str, dict[str, Any]] = {
    "healthcare": {
        "name": "healthcare",
        "description": (
            "Long confidentiality horizons dominate clinical records. Weights "
            "HNDL higher and reads the pessimistic survival curve."
        ),
        "w_H": 0.7,
        "w_T": 0.3,
        "survival_curve_reading": "pessimistic",
        "flag_threshold": 0.60,
    },
    "payments": {
        "name": "payments",
        "description": (
            "Payment HSMs and trust anchors dominate. Weights integrity higher "
            "while keeping the median survival reading."
        ),
        "w_H": 0.4,
        "w_T": 0.6,
    },
    "government": {
        "name": "government",
        "description": (
            "Statutory dates already bind. Strict verification flag with equal "
            "axis weights and a pessimistic survival reading."
        ),
        "survival_curve_reading": "pessimistic",
        "flag_threshold": 0.65,
    },
    "telecom": {
        "name": "telecom",
        "description": "Edge exposure is high; confidentiality weighted up.",
        "w_H": 0.6,
        "w_T": 0.4,
    },
    "energy": {
        "name": "energy",
        "description": "OT trust anchors dominate; integrity weighted up.",
        "w_H": 0.35,
        "w_T": 0.65,
        "survival_curve_reading": "pessimistic",
    },
    "erp": {
        "name": "erp",
        "description": "Balanced estate posture for enterprise application stacks.",
    },
}


def sector_defaults(sector: str) -> EnginePolicy:
    """Load sector-oriented defaults, preferring content from ``engine.packs``.

    Packs today carry compliance content rather than numeric policy. When a pack
    for ``sector`` is registered we stamp its id/version into the description
    and apply a documented overlay if one exists; otherwise we return balanced.
    """
    base = balanced_policy()
    sector_key = (sector or "").strip().lower()
    pack = None
    try:
        from engine.packs import PACKS

        for candidate in PACKS.values():
            if candidate.sector == sector_key or candidate.id == sector_key:
                pack = candidate
                break
            if candidate.id.endswith(f".{sector_key}"):
                pack = candidate
                break
    except Exception:
        pack = None

    overlay = dict(_SECTOR_OVERLAYS.get(sector_key, {}))
    if pack is not None:
        # Future packs may carry an explicit ``engine_policy`` mapping.
        extra = getattr(pack, "engine_policy", None)
        if isinstance(extra, dict):
            overlay.update(extra)
        base.name = f"sector:{pack.sector}"
        base.preset = None
        base.description = (
            f"Defaults for sector '{pack.sector}' from pack {pack.id} "
            f"v{pack.version}. {overlay.get('description', base.description)}"
        )
        base.version = f"pack-{pack.version}"
    elif overlay:
        base.name = overlay.get("name", f"sector:{sector_key}")
        base.preset = None
        base.description = overlay.get("description", base.description)
    else:
        base.name = f"sector:{sector_key or '*'}"
        base.preset = None
        base.description = (
            f"No pack-specific policy for '{sector_key or '*'}'; returning "
            "balanced engine defaults."
        )
        return base

    for key in (
        "w_H", "w_T", "flag_threshold", "survival_curve_reading",
        "risk_bands", "provenance_confidences",
        "input_defaults", "asset_class_inputs",
    ):
        if key in overlay:
            setattr(base, key, copy.deepcopy(overlay[key]))
    return base


def validate_policy(data: dict[str, Any] | EnginePolicy) -> EnginePolicy:
    """Validate and normalise a policy document. Raises ValueError on bad input."""
    if isinstance(data, EnginePolicy):
        data = data.to_dict()
    if not isinstance(data, dict):
        raise ValueError("Policy must be a JSON object.")

    base = balanced_policy().to_dict()
    incoming = {k: v for k, v in data.items() if v is not None}
    merged = {**base, **incoming}
    # Preset is sticky only when the caller set it (or the name is a known preset).
    if "preset" not in data:
        merged["preset"] = merged["name"] if merged.get("name") in PRESETS else None
    elif data.get("preset") is None:
        merged["preset"] = None

    try:
        w_h = float(merged["w_H"])
        w_t = float(merged["w_T"])
    except (TypeError, ValueError, KeyError) as exc:
        raise ValueError("w_H and w_T must be numbers.") from exc
    if w_h < 0 or w_t < 0:
        raise ValueError("w_H and w_T must be non-negative.")
    total = w_h + w_t
    if total <= 0:
        raise ValueError("w_H + w_T must be positive.")
    # Allow unnormalised weights but keep them finite.
    if w_h > 1.0 or w_t > 1.0:
        raise ValueError("w_H and w_T must each be at most 1.0.")

    reading = merged.get("survival_curve_reading", "median")
    if reading not in SURVIVAL_READINGS:
        raise ValueError(
            f"survival_curve_reading must be one of {', '.join(SURVIVAL_READINGS)}."
        )

    try:
        flag_threshold = float(merged["flag_threshold"])
    except (TypeError, ValueError, KeyError) as exc:
        raise ValueError("flag_threshold must be a number.") from exc
    if not 0.0 <= flag_threshold <= 1.0:
        raise ValueError("flag_threshold must be in [0, 1].")

    bands = merged.get("risk_bands") or _BALANCED_RISK_BANDS
    if not isinstance(bands, list) or not bands:
        raise ValueError("risk_bands must be a non-empty list.")
    normalised_bands: list[dict[str, Any]] = []
    for entry in bands:
        if isinstance(entry, (list, tuple)) and len(entry) == 2:
            threshold, level = entry
            entry = {"threshold": threshold, "level": level}
        if not isinstance(entry, dict) or "threshold" not in entry or "level" not in entry:
            raise ValueError(
                "Each risk band needs {threshold, level}."
            )
        try:
            threshold = float(entry["threshold"])
        except (TypeError, ValueError) as exc:
            raise ValueError("risk band threshold must be a number.") from exc
        if not 0.0 <= threshold <= 1.0:
            raise ValueError("risk band thresholds must be in [0, 1].")
        normalised_bands.append({
            "threshold": threshold,
            "level": str(entry["level"]),
        })

    provenance = merged.get("provenance_confidences") or {}
    if not isinstance(provenance, dict):
        raise ValueError("provenance_confidences must be an object.")
    provenance = {str(k): float(v) for k, v in provenance.items()}
    if any(not 0.0 <= v <= 1.0 for v in provenance.values()):
        raise ValueError("provenance confidences must be in [0, 1].")

    input_defaults = merged.get("input_defaults") or dict(_GENERIC_INPUTS)
    if not isinstance(input_defaults, dict):
        raise ValueError("input_defaults must be an object.")
    for key in ("x_c", "x_i", "y", "s", "e", "c"):
        if key not in input_defaults:
            raise ValueError(f"input_defaults missing '{key}'.")
        input_defaults[key] = float(input_defaults[key])

    asset_class = merged.get("asset_class_inputs") or {}
    if not isinstance(asset_class, dict):
        raise ValueError("asset_class_inputs must be an object.")
    cleaned_classes: dict[str, dict[str, float]] = {}
    for class_name, values in asset_class.items():
        if not isinstance(values, dict):
            raise ValueError(f"asset_class_inputs[{class_name!r}] must be an object.")
        cleaned_classes[str(class_name)] = {
            k: float(values[k]) for k in ("x_c", "x_i", "y", "s", "e", "c")
            if k in values
        }

    preset_name = merged.get("preset")
    if preset_name is not None:
        preset_name = str(preset_name)
        if preset_name and preset_name not in PRESETS:
            # Custom saved policies may clear preset; unknown names are rejected.
            raise ValueError(
                f"Unknown preset {preset_name!r}. One of: "
                f"{', '.join(sorted(PRESETS))}."
            )

    return EnginePolicy(
        version=str(merged.get("version") or "1.0.0"),
        name=str(merged.get("name") or "custom"),
        description=str(merged.get("description") or ""),
        w_H=w_h,
        w_T=w_t,
        risk_bands=normalised_bands,
        flag_threshold=flag_threshold,
        provenance_confidences=provenance,
        survival_curve_reading=reading,  # type: ignore[arg-type]
        input_defaults={k: float(v) for k, v in input_defaults.items()},
        asset_class_inputs=cleaned_classes,
        preset=preset_name or None,
    )


def resolve_policy(policy: EnginePolicy | dict | None = None) -> EnginePolicy:
    """Normalise an optional policy argument for ``scan_pipeline.run``.

    ``None`` always means the balanced ship defaults, so existing call sites
    keep today's behaviour. The API passes ``get_current()`` explicitly when
    the operator has saved a different document.
    """
    if policy is None:
        return balanced_policy()
    if isinstance(policy, EnginePolicy):
        return policy
    return validate_policy(policy)


# --------------------------------------------------------------------------
# Process-scoped current policy (persisted when saved via the API)
# --------------------------------------------------------------------------

_current: EnginePolicy | None = None


def get_current() -> EnginePolicy:
    global _current
    if _current is not None:
        return copy.deepcopy(_current)
    loaded = _load_from_disk()
    if loaded is not None:
        _current = loaded
        return copy.deepcopy(_current)
    _current = balanced_policy()
    return copy.deepcopy(_current)


def set_current(policy: EnginePolicy | dict) -> EnginePolicy:
    global _current
    validated = validate_policy(policy if isinstance(policy, dict) else policy.to_dict())
    _current = validated
    _save_to_disk(validated)
    return copy.deepcopy(_current)


def reset_current() -> EnginePolicy:
    """Restore balanced defaults (tests and import paths)."""
    global _current
    _current = balanced_policy()
    if POLICY_FILE.exists():
        try:
            POLICY_FILE.unlink()
        except OSError:
            pass
    return copy.deepcopy(_current)


def _load_from_disk() -> EnginePolicy | None:
    if not POLICY_FILE.exists():
        return None
    try:
        raw = json.loads(POLICY_FILE.read_text(encoding="utf-8"))
        return validate_policy(raw)
    except (OSError, json.JSONDecodeError, ValueError):
        return None


def _save_to_disk(policy: EnginePolicy) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    POLICY_FILE.write_text(
        json.dumps(policy.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def survival_index(reading: str | None) -> int:
    """Map a survival-curve reading name to the ThreatModel.survival() tuple index."""
    key = reading if reading in SURVIVAL_READINGS else "median"
    return SURVIVAL_READINGS.index(key)  # type: ignore[arg-type]


def risk_band_tuples(policy: EnginePolicy | None = None) -> list[tuple[float, str]]:
    """RISK_BANDS-shaped list for assign_risk_level-style callers."""
    pol = policy or get_current()
    return [(float(b["threshold"]), str(b["level"])) for b in pol.risk_bands]


def compare_rankings(
    current_ranked: list[dict],
    proposed_ranked: list[dict],
) -> dict[str, Any]:
    """Diff two ranked lists for the policy preview endpoint."""
    current_pos = {r["id"]: r.get("rank") for r in current_ranked}
    proposed_pos = {r["id"]: r.get("rank") for r in proposed_ranked}
    moves = []
    for asset_id, new_rank in proposed_pos.items():
        old_rank = current_pos.get(asset_id)
        if old_rank is None or new_rank is None or old_rank == new_rank:
            continue
        name = next(
            (r.get("name", asset_id) for r in proposed_ranked if r["id"] == asset_id),
            asset_id,
        )
        moves.append({
            "id": asset_id,
            "name": name,
            "from_rank": old_rank,
            "to_rank": new_rank,
            "delta": old_rank - new_rank,  # positive = moved up
        })
    # Assets present in only one of the two rankings
    entered = [
        {"id": i, "to_rank": proposed_pos[i]}
        for i in proposed_pos
        if i not in current_pos
    ]
    exited = [
        {"id": i, "from_rank": current_pos[i]}
        for i in current_pos
        if i not in proposed_pos
    ]
    moves.sort(key=lambda m: abs(m["delta"]), reverse=True)
    return {
        "moved_count": len(moves),
        "rank_moves": moves,
        "entered_ranking": entered,
        "left_ranking": exited,
    }
