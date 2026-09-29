"""Deterministic intent router: requests whose verb names the tool never reach the model.

WHY
---
On the local default (qwen3:1.7b), asked to *migrate* an asset, the model called
`preview_migration`. Asked to explain an asset by name, it passed a word lifted
from the sentence as the asset id. Both are selection mistakes, not language
mistakes, and both are cheap to avoid: when the sentence starts with "migrate",
the tool is `migrate_asset`, and the asset is whichever one the rest of the
sentence names. A regex over the normalised text decides that before the model
is asked anything; the model is then given the tool result to phrase.

RULES
-----
* **Never guess an asset.** The reference is matched against asset ids, names,
  file names, systems and algorithms. One candidate: proceed. Several: ask the
  user to pick, listing them. None, after an explicit verb like "migrate": say
  so. A "why" question whose words match no asset is left to the model, since
  it is probably about a concept ("why is RSA weak").
* **Never bypass the control plane.** A routed call is executed by
  `engine.agent.execute_tool`, exactly like a model's call, so read-only mode,
  the blast-radius cap, the rate limit and the audit chain all still apply.
* **Precision over recall.** A pattern that could misfire is not here; anything
  unmatched goes to the model with tools, as before. `bench/agent_bench.py`
  measures both arms on 30 labelled prompts.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from pathlib import PurePath

MAX_CANDIDATES = 6

# Words that say what kind of question it is, not which asset it is about.
STOPWORDS = frozenset("""
a an the this that these those it its is are was were be been being do does did has have had
of for to in on at by with from as and or but so very such much more most me my our we us you your
i what which who whom whose why how when where explain show tell give list please can could would
should will shall may might just about asset assets ranked rank ranking ranks ranked high higher highest
top first second third fourth fifth last so risky risk risks riskier urgent urgently critical priority
prioritised prioritized score scored scores scoring flagged flag problem problems vulnerable exposed
dangerous important bad worse worst number one ahead above there here now today still
mosca evidence confident confidence sure certain reading inequality horizon quantum computer crqc
become becomes breakable broken safe
""".split())

SURFACE_WORDS = {
    "source": "source", "code": "source", "repos": "source", "repositories": "source",
    "dependency": "dependency", "dependencies": "dependency", "packages": "dependency",
    "sbom": "dependency", "lockfiles": "dependency",
    "binary": "binary", "binaries": "binary", "executables": "binary",
    "container": "container", "containers": "container", "images": "container", "image": "container",
    "config": "config", "configs": "config", "configuration": "config", "configurations": "config",
    "keystore": "keystore", "keystores": "keystore", "certificates": "keystore", "certs": "keystore",
    "secret": "secret", "secrets": "secret",
    "vault": "vault", "vaults": "vault", "hsm": "vault", "kms": "vault", "kmip": "vault",
    "capture": "capture", "captures": "capture", "pcap": "capture", "recordings": "capture",
}

_POLITE = re.compile(
    r"^(?:(?:hey|hi|ok|okay|so|now|vera)[,\s]+)*"
    r"(?:(?:please|pls|kindly)\s+)?"
    r"(?:(?:can|could|would|will)\s+you\s+(?:please\s+)?)?"
    r"(?:(?:i\s+want\s+(?:you\s+)?to|i'?d\s+like\s+(?:you\s+)?to|let'?s)\s+)?"
    r"(?:please\s+)?"
)
_TO_TARGET = re.compile(
    r"\s+(?:to|onto|into)\s+(?:a\s+|the\s+)?(?:hybrid|pqc(?:[- ]only)?|pure\s+pqc|post[- ]quantum|"
    r"ml-kem\S*|ml-dsa\S*|slh-dsa\S*|quantum[- ]safe|pq)\b.*$"
)
_RANK_REF = re.compile(r"(?:\brank(?:ed)?\s*#?\s*|#|\bnumber\s+|\bno\.\s*)(\d{1,4})\b")
_TOP_REF = re.compile(r"\b(?:top(?:[- ]ranked)?\s+asset|highest[- ]ranked(?:\s+asset)?|number\s+one|first\s+asset)\b")
_WHOLE_ESTATE = re.compile(r"^(?:all|everything|every\s+asset|all\s+(?:the\s+)?assets|the\s+(?:whole|entire)\s+estate"
                           r"|(?:the\s+)?estate|all\s+\d+\s+assets|\d+\s+assets)$")
_SCOPE = re.compile(r"^(?:all|every(?:thing)?)(?:\s+(?:the\s+)?assets?)?\s+(?:in|on|under|from)\s+(?P<scope>.+)$")


@dataclass
class Route:
    """What the router decided for one message."""

    kind: str                     # "tool" | "clarify"
    rule: str                     # the pattern that matched, for the audit and the benchmark
    tool: str | None = None
    arguments: dict = field(default_factory=dict)
    question: str = ""            # for "clarify": what to ask the user
    candidates: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


# --------------------------------------------------------------------------
# Text and asset matching
# --------------------------------------------------------------------------


def normalise(text: str) -> str:
    """Lower-case, collapse whitespace, drop trailing punctuation and polite openers."""
    text = re.sub(r"\s+", " ", str(text or "").strip().lower())
    text = text.rstrip(" ?!.")
    text = text.replace("’", "'")
    return _POLITE.sub("", text).strip()


def _words(text: str) -> list[str]:
    """Split on whitespace; strip wrapping punctuation and possessives."""
    out = []
    for raw in text.split():
        word = raw.strip(",;:!?\"'()[]{}<>`")
        word = re.sub(r"'s$", "", word)
        if word:
            out.append(word)
    return out


def _parts(token: str) -> set[str]:
    """A token and its pieces: 'auth.ts:6' -> {'auth.ts:6', 'auth.ts', '6', 'auth', 'ts'}."""
    token = token.strip(",;!?\"'()[]{}<>`")
    parts = {token}
    for piece in re.split(r"[:/\\()]", token):
        if piece:
            parts.add(piece)
            parts.update(p for p in re.split(r"[._\-]", piece) if p)
    return parts


def _haystack(asset) -> set[str]:
    details = getattr(asset, "raw_details", None) or {}
    location = str(getattr(asset, "source_location", "") or "")
    fields = [
        getattr(asset, "name", "") or "", PurePath(location.replace("\\", "/").split("!")[-1]).name,
        location.split("!")[0].rsplit("/", 1)[-1], str(details.get("system") or ""),
        getattr(asset, "algorithm", "") or "", getattr(asset, "asset_class", "") or "",
    ]
    tokens: set[str] = set()
    for text in fields:
        for word in str(text).lower().split():
            tokens |= _parts(word)
    return tokens


def _singular(word: str) -> str:
    return word[:-1] if len(word) > 3 and word.endswith("s") and not word.endswith("ss") else word


def _brief(asset) -> dict:
    return {"id": asset.id, "name": asset.name, "priority_rank": asset.priority_rank,
            "system": (getattr(asset, "raw_details", None) or {}).get("system")}


def reference_tokens(reference: str) -> list[str]:
    """The words of a reference that could name an asset."""
    words = _words(normalise(reference))
    return [w for w in words if w not in STOPWORDS and not re.fullmatch(r"\d+(?:st|nd|rd|th)", w)]


def resolve(reference: str, assets) -> list:
    """Every asset the reference could mean, best-ranked first. Never picks among them."""
    text = normalise(reference)
    if not text or not assets:
        return []
    for asset in assets:
        if asset.id.lower() == text or (len(text) >= 8 and re.fullmatch(r"[0-9a-f-]+", text)
                                        and asset.id.lower().startswith(text)):
            return [asset]
    exact = [a for a in assets if (a.name or "").lower() == text]
    if len(exact) == 1:
        return exact

    for word in _words(text):
        if len(word) >= 8 and re.fullmatch(r"[0-9a-f-]+", word):
            by_id = [a for a in assets if a.id.lower().startswith(word)]
            if by_id:
                return by_id

    # "rank 3" and "the top asset" name a position, not words in a name.
    rank = _rank_of(text)
    tokens = reference_tokens(_TOP_REF.sub(" ", _RANK_REF.sub(" ", text)) if rank else text)
    if not tokens:
        return [a for a in assets if a.priority_rank == rank] if rank else []

    matches = []
    for asset in assets:
        hay = _haystack(asset)
        if all(t in hay or _singular(t) in hay for t in tokens):
            matches.append(asset)
    return sorted(matches, key=lambda a: (a.priority_rank or 10**9, a.name or ""))


def _rank_of(text: str) -> int | None:
    if _TOP_REF.search(text):
        return 1
    found = _RANK_REF.search(text)
    return int(found.group(1)) if found else None


def _pick(reference: str, assets, *, rule: str, tool: str, arguments: dict,
          on_none: str | None) -> Route | None:
    """One candidate: route. Several: ask. None: say so (on_none) or defer to the model (None)."""
    candidates = resolve(reference, assets)
    if len(candidates) == 1:
        return Route("tool", rule, tool, {**arguments, "asset_id": candidates[0].id})
    if len(candidates) > 1:
        shown = candidates[:MAX_CANDIDATES]
        lines = "\n".join(f"{i}. {a.name} (rank {a.priority_rank}, id {a.id})" for i, a in enumerate(shown, 1))
        more = f"\n...and {len(candidates) - len(shown)} more." if len(candidates) > len(shown) else ""
        return Route("clarify", rule, tool, arguments, candidates=[_brief(a) for a in shown],
                     question=(f"{len(candidates)} assets match \"{reference.strip()}\". Which one do you mean?\n"
                               f"{lines}{more}\nReply with the number, the name or the id."))
    if on_none is None:
        return None
    return Route("clarify", rule, tool, arguments,
                 question=on_none.format(reference=reference.strip()))


# --------------------------------------------------------------------------
# Patterns
# --------------------------------------------------------------------------


def _migrate(text: str, assets) -> Route | None:
    found = re.match(r"^migrate\s+(?P<ref>.+)$", text)
    if not found:
        # "move" and "upgrade" say migrate only with a post-quantum destination:
        # "move on" and "upgrade the report" are not migrations.
        moved = re.match(r"^(?:move|upgrade|switch)\s+(?P<ref>.+)$", text)
        found = moved if moved and _TO_TARGET.search(moved.group("ref")) else None
    if not found:
        return None
    strategy = "pqc_only" if re.search(r"\bpqc[- ]only\b|\bpure\s+pqc\b|\bwithout\s+(?:a\s+)?(?:classical\s+)?fallback\b",
                                        text) else "hybrid"
    ref = _TO_TARGET.sub("", found.group("ref")).strip()
    ref = re.sub(r"\s+(?:as\s+|using\s+)?(?:pqc[- ]only|pure\s+pqc|hybrid|without\s+(?:a\s+)?(?:classical\s+)?"
                 r"fallback)$", "", ref)
    ref = re.sub(r"\s+(?:now|today|immediately|first)$", "", ref)
    if _WHOLE_ESTATE.match(ref):
        return Route("tool", "migrate.estate", "migrate_asset", {"target": "", "strategy": strategy})
    scope = _SCOPE.match(ref)
    if scope:
        return Route("tool", "migrate.scope", "migrate_asset", {"target": scope.group("scope"), "strategy": strategy})
    return _pick(ref, assets, rule="migrate.asset", tool="migrate_asset", arguments={"strategy": strategy},
                 on_none="No asset matches \"{reference}\", so nothing was proposed. "
                         "Ask me to list assets, then name one exactly.")


def _preview(text: str, assets) -> Route | None:
    found = (re.match(r"^(?:preview|dry[- ]run)(?:\s+(?:the\s+)?migrat\w*(?:\s+(?:of|for))?)?\s+(?P<ref>.+)$", text)
             or re.match(r"^what (?:would|will) (?:migrating|moving|upgrading) (?P<ref>.+?) (?:change|do)$", text))
    if not found:
        return None
    ref = _TO_TARGET.sub("", found.group("ref")).strip()
    if _WHOLE_ESTATE.match(ref):
        return Route("tool", "preview.estate", "preview_migration", {"target": ""})
    return _pick(ref, assets, rule="preview.asset", tool="preview_migration", arguments={},
                 on_none="No asset matches \"{reference}\". Ask me to list assets, then name one exactly.")


def _explain(text: str, assets) -> Route | None:
    found = re.match(r"^(?:why|explain|justify)\b(?P<rest>.*)$", text)
    mosca_q = re.match(r"^when (?:does|will|is) (?P<rest>.+?) (?:become |be |going to be )?"
                       r"(?:vulnerable|at risk|a problem|breakable|broken|unsafe)\b", text)
    sure_q = re.match(r"^how (?:sure|confident|certain) (?:are you|is vera|is the engine) (?:about|in|of|that) "
                      r"(?P<rest>.+)$", text)
    if not (found or mosca_q or sure_q):
        return None
    rest = (mosca_q or sure_q or found).group("rest")
    if sure_q:
        tool, rule = "explain_evidence", "explain.evidence"
    elif mosca_q or re.search(r"\bmosca\b|\bcrqc\b|\bquantum computer\b|\bwhen\b", text):
        tool, rule = "explain_mosca", "explain.mosca"
    elif re.search(r"\bevidence\b|\bconfiden\w*\b|\bsure\b|\bflagged\b|\bcertain\b", text):
        tool, rule = "explain_evidence", "explain.evidence"
    else:
        tool, rule = "explain_asset", "explain.asset"
    return _pick(rest, assets, rule=rule, tool=tool, arguments={}, on_none=None)


def _recommend(text: str, assets) -> Route | None:
    found = (re.match(r"^recommend(?:ation|ations)?\s+(?:a\s+)?(?:replacement\s+)?(?:for\s+)?(?P<ref>.+)$", text)
             or re.match(r"^what should (?P<ref>.+?) (?:move|migrate|change|be replaced) (?:to|with)$", text)
             or re.match(r"^what(?:'s| is) the (?:replacement|recommendation|recommended replacement|pqc replacement)"
                         r" for (?P<ref>.+)$", text))
    if not found:
        return None
    profile = "cnsa" if re.search(r"\bcnsa\b", text) else None
    ref = re.sub(r"\s+(?:under|with|using|for)\s+(?:the\s+)?(?:cnsa|commercial)(?:\s+2\.0)?(?:\s+profile)?$", "",
                 found.group("ref"))
    arguments = {"profile": profile} if profile else {}
    return _pick(ref, assets, rule="recommend.asset", tool="recommend", arguments=arguments,
                 on_none="No asset matches \"{reference}\". Ask me to list assets, then name one exactly.")


def _estate_level(text: str) -> Route | None:
    """Questions about the whole estate, where the tool follows from a keyword."""
    if re.match(r"^(?:run|start|do|kick off|launch|trigger)\s+(?:a\s+|the\s+)?(?:full\s+|new\s+|fresh\s+)?"
                r"(?:scan|discovery|rescan)\b", text) or re.match(r"^(?:rescan|re-scan)\b", text) \
            or re.match(r"^scan\s+(?:the\s+)?(?:estate|everything|demo estate|all surfaces)\b", text):
        surfaces = sorted({SURFACE_WORDS[w] for w in _words(text) if w in SURFACE_WORDS})
        return Route("tool", "scan.run", "run_scan", {"surfaces": surfaces} if surfaces else {})
    if re.search(r"\b(?:verify|check|validate)\b.*\b(?:manifest|signature|audit|evidence chain|chain)\b", text) \
            or re.search(r"\btamper(?:ed|ing)?\b", text):
        return Route("tool", "evidence.verify", "verify_manifest", {})
    if re.search(r"\b(?:compare|diff)\b.*\bscans?\b", text) or re.match(r"^what (?:has )?changed\b", text):
        return Route("tool", "scans.compare", "compare_scans", {})
    if re.match(r"^(?:show|list|any|what|which|how many|are there|is there)\b.*\bdrift\b", text) or text == "drift":
        arguments: dict = {}
        rule_ref = re.search(r"\bd([1-8])\b", text)
        if rule_ref:
            arguments["rule"] = f"D{rule_ref.group(1)}"
        severity = re.search(r"\b(critical|high|medium|low)\b", text)
        if severity:
            arguments["severity"] = severity.group(1)
        return Route("tool", "drift.list", "list_drift", arguments)
    if re.match(r"^(?:what|which|show|list|how many|who)\b.*\b(?:blocked|vendor|vendors|provider|providers|gated"
                r"|firmware)\b", text):
        return Route("tool", "gated.list", "list_vendor_gated", {})
    if re.match(r"^(?:what|which|show|list|how many)\b.*\b(?:flagged|verify first|confirm first|thin evidence"
                r"|weak evidence)\b", text):
        return Route("tool", "flagged.list", "list_flagged", {})
    if re.match(r"^(?:how many|count|number of)\b.*\b(?:assets?|keys?|certificates?|findings?|algorithms?)\b", text) \
            or re.match(r"^(?:give me |show me |show )?(?:an? |the )?(?:estate )?(?:summary|overview)"
                        r"(?: of (?:the )?estate)?$", text):
        return Route("tool", "estate.summary", "get_estate_summary", {})
    return None


_CLARIFY = re.compile(r"^\d+ assets match \".*\"\. Which one do you mean\?")
_CANDIDATE_LINE = re.compile(r"^(\d+)\. .* \(rank [^,]*, id ([^)]+)\)$", re.MULTILINE)


def route_conversation(messages: list[dict], assets) -> Route | None:
    """Route the newest user message, treating a reply to a pick-list as the pick.

    When the previous assistant turn was the router asking which asset was
    meant, a reply of "2", an id or a name that singles out one candidate
    re-runs the original request on that asset. Anything else is routed as a
    new message.
    """
    if not messages or messages[-1].get("role") != "user":
        return None
    reply = str(messages[-1].get("content") or "")
    if len(messages) >= 3 and messages[-2].get("role") == "assistant" and messages[-3].get("role") == "user":
        asked = str(messages[-2].get("content") or "")
        if _CLARIFY.match(asked):
            listed = dict(_CANDIDATE_LINE.findall(asked))
            by_id = {a.id: a for a in assets}
            candidates = [by_id[i] for i in listed.values() if i in by_id]
            answer = normalise(reply)
            if answer in listed and listed[answer] in by_id:
                chosen = [by_id[listed[answer]]]
            else:
                chosen = resolve(answer, candidates)
            if len(chosen) == 1:
                decision = route(str(messages[-3].get("content") or ""), chosen)
                if decision is not None and decision.kind == "tool":
                    decision.rule += ".picked"
                    return decision
    return route(reply, assets)


def route(message: str, assets) -> Route | None:
    """The deterministic decision for one user message, or None to ask the model."""
    text = normalise(message)
    if not text:
        return None
    for matcher in (_preview, _migrate, _recommend, _explain):
        decision = matcher(text, assets)
        if decision is not None:
            return decision
    return _estate_level(text)


# --------------------------------------------------------------------------
# Answers without a model
# --------------------------------------------------------------------------


def describe(decision: Route, result: dict) -> str:
    """A plain, number-for-number sentence from a tool result, for when no model is configured.

    Every figure is copied from `result`; nothing is computed or rounded here
    beyond formatting.
    """
    if result.get("error"):
        remedy = f" {result['remedy']}" if result.get("remedy") else ""
        return f"{result['error']}{remedy}"
    tool = decision.tool
    if result.get("status") == "awaiting_approval":
        return (f"Proposed, not applied: {result.get('summary')}. It needs a human approval on the "
                f"approval card (proposal {result.get('proposal_id')}).")
    if tool == "get_estate_summary":
        return (f"{result.get('total_assets')} assets: {result.get('quantum_vulnerable')} quantum-vulnerable, "
                f"{result.get('quantum_safe')} quantum-safe, {result.get('classically_broken')} classically broken; "
                f"{result.get('negative_slack_count')} cannot meet their statutory deadline "
                f"(sector track {result.get('org_persona')}).")
    if tool == "list_drift":
        summary = result.get("summary", {})
        return (f"{result.get('matching', 0)} drift record(s) match; the last full scan found "
                f"{summary.get('total', 0)} in all ({', '.join(f'{k} {v}' for k, v in summary.get('by_severity', {}).items())}).")
    if tool == "list_vendor_gated":
        return (f"{result.get('assets_gated', 0)} asset(s) are gated on {result.get('groups', 0)} vendor or "
                "provider group(s): " + "; ".join(f"{g['who']} ({g['count']})" for g in result.get("register", [])) + ".")
    if tool == "list_flagged":
        return f"{result.get('flagged_count', 0)} asset(s) are flagged for verification."
    if tool == "verify_manifest":
        manifest, chain = result.get("manifest", {}), result.get("audit_chain", {})
        chain_text = ("the audit chain is intact" if chain.get("valid")
                      else f"the audit chain is BROKEN at entry {chain.get('first_broken')}: {chain.get('reason')}")
        return (f"Manifest signature ({manifest.get('algorithm')}): "
                f"{'valid' if manifest.get('valid') else 'NOT valid'} - {manifest.get('reason')}; {chain_text} "
                f"({chain.get('entries')} entries).")
    if tool == "explain_mosca":
        return f"{result.get('name')}: {result.get('explanation') or result.get('label')}"
    if tool == "recommend":
        if not result.get("need"):
            return f"{result.get('name') or result.get('asset_id')}: no change needed. {result.get('why', '')}".strip()
        return (f"{result.get('asset')}: {result.get('need_label')} -> {result.get('recommended')} "
                f"({result.get('profile')} profile). {result.get('why', '')}".strip())
    if tool == "compare_scans":
        migration = result.get("migration", {})
        return (f"From {result['from']['label']} to {result['to']['label']}: {len(result.get('added', []))} added, "
                f"{len(result.get('removed', []))} removed, {len(result.get('changed', []))} changed; "
                f"{migration.get('migrated')} of {migration.get('vulnerable_before')} vulnerable assets migrated."
                + (f" {result['warning']}" if result.get("warning") else ""))
    if tool == "run_scan":
        outcome = result.get("result") or {}
        return (f"Scan {result.get('status')}: {outcome.get('assets')} assets, {outcome.get('quantum_vulnerable')} "
                f"quantum-vulnerable, {outcome.get('drift')} drift record(s).")
    return f"Ran {tool}. The full result is shown below."
