"""What the agents are actually asked to decide.

THE RULE THAT MAKES THIS SAFE
-----------------------------
Every task here returns a **graded reading**, never a number and never a
final answer. The model's output carries the `heuristic` provenance grade
(0.35 - the weakest that exists) and is always marked `requires_review`.

The consequence is worth stating plainly: **a wrong answer from a small free
model becomes a weak, reviewable reading instead of a confident mistake.** It
never changes a score or a rank, and a runtime observation at 0.98 always
outweighs it. That is why this is safe to run on a free tier.

Tasks are chosen to be *critical but doable*: each is a bounded reading problem
with a small answer space, which is what small models are actually good at.
None of them requires the model to compute, rank, or schedule.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

#: The grade any model-derived claim carries. Deliberately the weakest.
AGENT_PROVENANCE = "heuristic"
AGENT_CONFIDENCE = 0.35

_KNOWN_ALGORITHMS = {
    "RSA", "ECDSA", "ECDH", "ECDHE", "DH", "DSA", "Ed25519", "X25519",
    "AES", "3DES", "DES", "ChaCha20", "MD5", "SHA-1", "SHA-256", "SHA-512",
    "HMAC", "ML-KEM-768", "ML-DSA-65", "SLH-DSA", "unknown",
}


@dataclass
class AgentVerdict:
    """One model answer, already graded and labelled."""

    task: str
    answer: str
    rationale: str
    confidence: float = AGENT_CONFIDENCE
    provenance: str = AGENT_PROVENANCE
    requires_review: bool = True
    model: str = ""
    provider: str = ""

    def to_dict(self) -> dict:
        return {
            "task": self.task,
            "answer": self.answer,
            "rationale": self.rationale,
            "confidence": self.confidence,
            "provenance": self.provenance,
            "requires_review": self.requires_review,
            "model": self.model,
            "provider": self.provider,
            "note": (
                "A model's reading, graded as heuristic evidence. It is fused "
                "with every other sensor and can be outvoted by any stronger "
                "one. It sets no score and no rank."
            ),
        }


def _extract_json(text: str) -> dict | None:
    """Pull the first JSON object out of a model response.

    Small models wrap JSON in prose, fences, or both. Failing to parse is a
    normal outcome that returns None rather than raising - the engine then
    records that the task produced nothing, which is honest and recoverable.
    """
    if not text:
        return None
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    candidate = fenced.group(1) if fenced else None
    if candidate is None:
        brace = re.search(r"\{.*\}", text, re.S)
        candidate = brace.group(0) if brace else None
    if candidate is None:
        return None
    try:
        parsed = json.loads(candidate)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        return None


# --------------------------------------------------------------------------
# Task 1 - resolve an algorithm static analysis could not
# --------------------------------------------------------------------------

_RESOLVE_SYSTEM = (
    "You identify which cryptographic algorithm a code snippet uses. "
    "Answer only with JSON: {\"algorithm\": <name or 'unknown'>, "
    "\"reason\": <one short sentence>}. "
    "If the algorithm is chosen at runtime and cannot be determined from the "
    "snippet, answer 'unknown'. Guessing is worse than saying unknown."
)


def resolve_algorithm(pool, snippet: str, location: str) -> AgentVerdict | None:
    """Ask what algorithm an unresolved call site uses.

    This is the highest-value task available: static analysis already found the
    call site, so the model is only being asked to read local context - which is
    what it is good at - and the answer space is a closed list.
    """
    result = pool.call([
        {"role": "system", "content": _RESOLVE_SYSTEM},
        {"role": "user", "content": f"Location: {location}\n\n{snippet[:2000]}"},
    ])
    if not result.get("ok"):
        return None

    parsed = _extract_json(result["text"])
    if not parsed:
        return None

    algorithm = str(parsed.get("algorithm", "unknown")).strip()
    # A name outside the known set is treated as unknown rather than accepted.
    # Letting a model invent an algorithm name would poison the taxonomy.
    if algorithm not in _KNOWN_ALGORITHMS:
        matched = next(
            (k for k in _KNOWN_ALGORITHMS if k.lower() == algorithm.lower()), None
        )
        algorithm = matched or "unknown"

    return AgentVerdict(
        task="resolve_algorithm",
        answer=algorithm,
        rationale=str(parsed.get("reason", ""))[:240],
        model=result.get("model", ""),
        provider=result.get("provider", ""),
    )


# --------------------------------------------------------------------------
# Task 2 - adjudicate a conflict between sensors
# --------------------------------------------------------------------------

_ADJUDICATE_SYSTEM = (
    "Two sensors disagree about one cryptographic asset. Say which is more "
    "likely correct and why, in JSON: {\"favours\": <source name>, "
    "\"reason\": <one short sentence>, \"confident\": true|false}. "
    "Runtime observation usually beats static analysis, because configuration "
    "and reality diverge. If you cannot tell, set confident to false."
)


def adjudicate_conflict(pool, asset_name: str, observations: list) -> AgentVerdict | None:
    """Offer a view on which of two disagreeing sensors is right.

    This is a *suggestion for a human*, not a resolution. The engine still holds
    the asset for review; the agent's job is to make that review faster by
    saying which way the evidence leans and why.
    """
    described = "\n".join(
        f"- {o.source} claims '{o.claim}' at confidence {o.confidence:.2f}"
        f"{(' (' + o.detail + ')') if o.detail else ''}"
        for o in observations
    )
    result = pool.call([
        {"role": "system", "content": _ADJUDICATE_SYSTEM},
        {"role": "user", "content": f"Asset: {asset_name}\n\n{described}"},
    ])
    if not result.get("ok"):
        return None

    parsed = _extract_json(result["text"])
    if not parsed:
        return None

    sources = {o.source for o in observations}
    favours = str(parsed.get("favours", "")).strip()
    if favours not in sources:
        return None  # a verdict naming a sensor that did not report is useless

    return AgentVerdict(
        task="adjudicate_conflict",
        answer=favours,
        rationale=str(parsed.get("reason", ""))[:240],
        # An unconfident adjudication is worth even less than the base grade.
        confidence=AGENT_CONFIDENCE if parsed.get("confident") else AGENT_CONFIDENCE / 2,
        model=result.get("model", ""),
        provider=result.get("provider", ""),
    )


# --------------------------------------------------------------------------
# Task 3 - infer a likely owner for an unowned asset
# --------------------------------------------------------------------------

_OWNER_SYSTEM = (
    "Infer which team likely owns an infrastructure asset from its name and "
    "path. Answer JSON: {\"team\": <short team name or 'unknown'>, "
    "\"reason\": <one short sentence>}. Answer 'unknown' unless the naming "
    "clearly indicates a team."
)


def infer_owner(pool, asset_name: str, location: str) -> AgentVerdict | None:
    """Propose an owner for an asset nobody claimed.

    "Nobody knows who owns this key" is a real migration blocker, and a
    *proposal* a human confirms is far cheaper than an archaeology exercise.
    The answer is never written to the asset; it is offered for confirmation.
    """
    result = pool.call([
        {"role": "system", "content": _OWNER_SYSTEM},
        {"role": "user", "content": f"Asset: {asset_name}\nLocation: {location}"},
    ])
    if not result.get("ok"):
        return None

    parsed = _extract_json(result["text"])
    if not parsed:
        return None

    team = str(parsed.get("team", "unknown")).strip()
    if not team or team.lower() == "unknown":
        return None

    return AgentVerdict(
        task="infer_owner",
        answer=team[:60],
        rationale=str(parsed.get("reason", ""))[:240],
        model=result.get("model", ""),
        provider=result.get("provider", ""),
    )


TASKS = {
    "resolve_algorithm": {
        "label": "Resolve unknown algorithms",
        "why": (
            "Static analysis finds the call site but cannot say which algorithm "
            "runs when it is chosen at runtime. A reader often can."
        ),
        "target": "assets with verdict 'unknown'",
    },
    "adjudicate_conflict": {
        "label": "Adjudicate sensor conflicts",
        "why": (
            "When two sensors disagree the asset is flagged for verification. "
            "An agent says which way the evidence leans, so the review is faster."
        ),
        "target": "assets whose sensors disagree",
    },
    "infer_owner": {
        "label": "Propose owners",
        "why": (
            "An asset nobody owns cannot be scheduled. A proposal a human "
            "confirms is cheaper than archaeology."
        ),
        "target": "assets with no owner recorded",
    },
}
