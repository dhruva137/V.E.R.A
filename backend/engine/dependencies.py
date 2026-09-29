"""Dependency graph over the scanned estate.

This module is a **read-only projection**. It computes no risk, changes no
score, and holds no opinion the scoring engine does not already hold. It reads
assets that have already been classified, scored and ranked, and reports how
they are wired to each other.

WHY THIS EXISTS
---------------
`C` - blast radius - is one of the six QIRS policy inputs, and it is the least
intuitive of them. "This root CA has C = 1.0" means little on a slide. "Click
the root CA and watch sixty certificates light up" means the same thing and
lands immediately. The graph makes an existing input legible; it does not add
a new one.

WHERE THE EDGES COME FROM
-------------------------
Five sources, in descending order of how much they can be relied on. Every
edge carries its `derivation` so the UI can say which is which rather than
presenting all of them as equally solid.

``certificate-chain`` - **observed.** Read from the `cert_issuer` and
`cert_subject` fields the collectors record. If a certificate names an issuer
whose subject belongs to another asset in the estate, that is a real signing
relationship, and it is exactly what a chain-building library would resolve. In
the bundled estate 60 of 61 certificates resolve this way.

``shared-endpoint`` - **observed.** Assets discovered at the same
`source_location` are the same service: a TLS endpoint yields a certificate, a
key-exchange group and a cipher suite, and migrating one without the others
leaves the endpoint half-migrated. The certificate is treated as the anchor
because it is the identity the others hang off.

``same-key-pair`` - **observed.** A key held in a keystore, HSM or key manager and a certificate (or a live
endpoint) whose public keys hash the same are one key pair: rotating the key re-issues the certificate.

``uses-library`` - **observed.** An algorithm found in a binary or image *through* a named crypto library (the
binary scanner records `via_library`) depends on that library in the same image or file: upgrading the library
is what migrates the algorithm.

``trust-anchor`` - **inferred**, and labelled as such. A firmware signing key
and the device fleet that verifies it share a tag in the synthetic estate, but
nothing in a scan proves the link; on a real estate this would come from a CMDB
or a deployment manifest. Shown because the blast radius of a signing anchor is
the whole point, and honest about being an inference.

Nothing here is presented as real bank infrastructure. The underlying estate is
synthetic and says so.
"""

from __future__ import annotations

from collections import defaultdict, deque

from models.schemas import CryptoAsset

# Edge kinds, with the provenance the UI displays alongside them.
EDGE_KINDS = {
    "certificate-chain": {
        "label": "issued by",
        "derivation": "observed",
        "description": (
            "Read from the certificate's issuer field, resolved against subjects "
            "elsewhere in the estate. The same relationship a chain-building "
            "library would follow."
        ),
    },
    "shared-endpoint": {
        "label": "same service",
        "derivation": "observed",
        "description": (
            "Discovered at the same host and port. A TLS endpoint's certificate, "
            "key exchange and cipher suite migrate together or not at all."
        ),
    },
    "same-key-pair": {
        "label": "same key pair",
        "derivation": "observed",
        "description": (
            "The public keys hash the same: a held key and the certificate or endpoint that presents it. "
            "Rotating one means re-issuing the other."
        ),
    },
    "uses-library": {
        "label": "uses library",
        "derivation": "observed",
        "description": (
            "The binary scanner found this algorithm through the named crypto library in the same image or "
            "file. Upgrading that library is what migrates it."
        ),
    },
    "trust-anchor": {
        "label": "trusted by",
        "derivation": "inferred",
        "description": (
            "Inferred from shared subsystem tags in the synthetic estate. On a "
            "real estate this would come from a CMDB or deployment manifest, not "
            "from a scan."
        ),
    },
}

# Asset classes that act as trust anchors for a subsystem rather than as one
# endpoint among many.
_ANCHOR_CLASSES = {
    "root_ca", "issuing_ca", "code_signing", "firmware_signing",
    "payment_hsm", "token_signing",
}

# Tags specific enough to imply a subsystem. Environment and generic labels are
# excluded, or every asset in production would be joined to every other.
_GENERIC_TAGS = {
    "production", "staging", "dr", "legacy", "infra", "live-scan",
    "keystore-scan", "config-scan", "source-scan", "code", "pki", "firmware",
}


def _hex(value) -> str:
    return "".join(c for c in str(value or "").lower() if c in "0123456789abcdef")


def _scope(asset: CryptoAsset) -> str:
    """The image an asset was found in, or else the file (the part of the location before any "!" or "@")."""
    d = asset.raw_details or {}
    return d.get("image_digest") or (asset.source_location or "").split("!")[0].split("@")[0]


def _subject_index(assets: list[CryptoAsset]) -> dict[str, CryptoAsset]:
    """Certificate subject -> the asset holding it."""
    index: dict[str, CryptoAsset] = {}
    for asset in assets:
        if asset.cert_subject:
            index.setdefault(asset.cert_subject, asset)
    return index


def _build_edges(assets: list[CryptoAsset]) -> list[dict]:
    """Every edge, deduplicated, each carrying its provenance."""
    by_subject = _subject_index(assets)
    edges: list[dict] = []
    seen: set[tuple[str, str, str]] = set()

    def add(source: str, target: str, kind: str) -> None:
        # `source` depends on `target`; target is upstream.
        if source == target:
            return
        key = (source, target, kind)
        if key in seen:
            return
        seen.add(key)
        edges.append({"source": source, "target": target, "kind": kind})

    # --- Certificate chains -------------------------------------------------
    for asset in assets:
        if not asset.cert_issuer:
            continue
        issuer = by_subject.get(asset.cert_issuer)
        # A self-signed root names itself; that is not a dependency.
        if issuer and issuer.id != asset.id:
            add(asset.id, issuer.id, "certificate-chain")

    # --- Shared endpoints ---------------------------------------------------
    by_location: dict[str, list[CryptoAsset]] = defaultdict(list)
    for asset in assets:
        by_location[asset.source_location].append(asset)

    for group in by_location.values():
        if len(group) < 2:
            continue
        # Anchor on the certificate where there is one, since that is the
        # identity the rest of the endpoint depends on.
        anchor = next((a for a in group if a.cert_subject), group[0])
        for asset in group:
            if asset.id != anchor.id:
                add(asset.id, anchor.id, "shared-endpoint")

    # --- Same key pair ------------------------------------------------------
    by_key: dict[str, list[CryptoAsset]] = defaultdict(list)
    for asset in assets:
        fp = _hex((asset.raw_details or {}).get("public_key_sha256"))
        if len(fp) >= 32:
            by_key[fp[:32]].append(asset)
    for group in by_key.values():
        if len(group) < 2:
            continue
        anchor = next((a for a in group if a.cert_subject), group[0])
        for asset in group:
            if asset.id != anchor.id:
                add(asset.id, anchor.id, "same-key-pair")

    # --- Algorithms reached through a named library -------------------------
    libraries: dict[tuple[str, str], CryptoAsset] = {}
    for asset in assets:
        d = asset.raw_details or {}
        if asset.asset_class == "crypto_library" and d.get("library_id"):
            libraries.setdefault((_scope(asset), d["library_id"]), asset)
    for asset in assets:
        via = (asset.raw_details or {}).get("via_library")
        lib = libraries.get((_scope(asset), via)) if via else None
        if lib is not None:
            add(asset.id, lib.id, "uses-library")

    # --- Trust anchors ------------------------------------------------------
    by_tag: dict[str, list[CryptoAsset]] = defaultdict(list)
    for asset in assets:
        for tag in asset.tags or []:
            if tag.lower() not in _GENERIC_TAGS:
                by_tag[tag.lower()].append(asset)

    for anchor in assets:
        if anchor.asset_class not in _ANCHOR_CLASSES:
            continue
        for tag in anchor.tags or []:
            tag = tag.lower()
            if tag in _GENERIC_TAGS:
                continue
            members = by_tag.get(tag, [])
            # A tag shared by most of the estate says nothing useful.
            if len(members) > 40:
                continue
            for member in members:
                if member.id == anchor.id or member.asset_class in _ANCHOR_CLASSES:
                    continue
                add(member.id, anchor.id, "trust-anchor")

    return edges


def _transitive_dependents(node_ids: list[str], edges: list[dict]) -> dict[str, int]:
    """How many assets ultimately depend on each node.

    This is blast radius made literal: the count of everything that would be
    affected, directly or through a chain, if this asset were compromised or
    withdrawn. It is derived from the graph, not from the `C` policy input, and
    the two are reported side by side so a reader can compare them.
    """
    incoming: dict[str, list[str]] = defaultdict(list)
    for edge in edges:
        incoming[edge["target"]].append(edge["source"])

    counts: dict[str, int] = {}
    for node_id in node_ids:
        seen: set[str] = set()
        queue = deque(incoming.get(node_id, []))
        while queue:
            current = queue.popleft()
            if current in seen or current == node_id:
                continue
            seen.add(current)
            queue.extend(incoming.get(current, []))
        counts[node_id] = len(seen)
    return counts


def _evidence_for(asset: CryptoAsset) -> dict:
    """Corroborate this asset's sensor readings so the node carries evidence quality.

    Reuses the pipeline's own corroboration rather than a second, drifting copy.
    Failures are contained: a graph must still draw if one node's evidence is
    malformed.
    """
    try:
        from engine.core.corroboration import for_asset

        ev = for_asset(asset)
        return {
            "confidence": ev["confidence"],
            "planes": ev["planes"],
            "evidence_sources": ev["sources"],
            "flagged": ev["flagged"],
            "flag_reason": ev["flag_reason"],
            "disagreement": ev["disagreement"],
        }
    except Exception:  # noqa: BLE001 - never let evidence break the graph
        return {
            "confidence": 0.0,
            "planes": {},
            "evidence_sources": [],
            "flagged": True,
            "flag_reason": "Evidence could not be read for this asset.",
            "disagreement": False,
        }


def build_graph(assets: list[CryptoAsset]) -> dict:
    """Project the scored estate into nodes and edges."""
    if not assets:
        return {
            "nodes": [], "edges": [], "edge_kinds": EDGE_KINDS,
            "stats": {"nodes": 0, "edges": 0}, "note": "No scan data.",
        }

    edges = _build_edges(assets)
    ids = [a.id for a in assets]
    dependents = _transitive_dependents(ids, edges)

    degree_out: dict[str, int] = defaultdict(int)
    degree_in: dict[str, int] = defaultdict(int)
    for edge in edges:
        degree_out[edge["source"]] += 1
        degree_in[edge["target"]] += 1

    nodes = []
    for asset in assets:
        nodes.append({
            "id": asset.id,
            "name": asset.name,
            "location": asset.source_location,
            "asset_class": asset.asset_class,
            "class_label": asset.profile_label,
            "source_type": asset.source_type,
            "discovered_by": (asset.raw_details or {}).get("discovered_by"),
            "system": (asset.raw_details or {}).get("system"),
            "persona": asset.persona,
            # Scores are copied verbatim from the scoring engine.
            "verdict": asset.verdict,
            "risk_level": asset.risk_level,
            "quantum_vulnerable": asset.quantum_vulnerable,
            "classically_broken": asset.classically_broken,
            "h_score": asset.h_score,
            "t_score": asset.t_score,
            "qirs": asset.qirs,
            "qirs_low": asset.qirs_low,
            "qirs_high": asset.qirs_high,
            "blast_radius_input": asset.c,
            "migration_years": asset.y,
            "deadline_year": asset.statutory_deadline_year,
            "slack_months": asset.slack_months,
            "priority_rank": asset.priority_rank,
            "algorithm": asset.algorithm or asset.key_exchange or asset.cipher_suite,
            "pqc_replacement": asset.pqc_replacement,
            # Graph-derived.
            "dependents": dependents.get(asset.id, 0),
            "depends_on_count": degree_out.get(asset.id, 0),
            "direct_dependents": degree_in.get(asset.id, 0),
            # Evidence quality, carried onto the graph so a node's colour can
            # distinguish "we know this is bad" from "we have barely looked at
            # it". A large, confidently-scored node and a large node nobody has
            # observed are completely different problems, and until now the
            # graph drew them identically.
            **_evidence_for(asset),
        })

    max_dependents = max((n["dependents"] for n in nodes), default=0)
    top = sorted(nodes, key=lambda n: -n["dependents"])[:5]

    # The most dangerous combination in any estate: heavily depended upon, and
    # barely observed. Surfaced explicitly because it is invisible in a graph
    # that only encodes risk.
    unseen_anchors = sorted(
        (n for n in nodes if n["dependents"] >= 3 and n["confidence"] < 0.60),
        key=lambda n: (-n["dependents"], n["confidence"]),
    )[:10]

    return {
        "nodes": nodes,
        "edges": edges,
        "edge_kinds": EDGE_KINDS,
        "stats": {
            "nodes": len(nodes),
            "edges": len(edges),
            "by_kind": {
                kind: sum(1 for e in edges if e["kind"] == kind) for kind in EDGE_KINDS
            },
            "observed_edges": sum(
                1 for e in edges if EDGE_KINDS[e["kind"]]["derivation"] == "observed"
            ),
            "inferred_edges": sum(
                1 for e in edges if EDGE_KINDS[e["kind"]]["derivation"] == "inferred"
            ),
            "max_dependents": max_dependents,
            "most_depended_on": [
                {"id": n["id"], "name": n["name"], "dependents": n["dependents"]}
                for n in top
            ],
            "disagreement_nodes": sum(1 for n in nodes if n["disagreement"]),
            "flagged_nodes": sum(1 for n in nodes if n["flagged"]),
            "multi_plane_nodes": sum(1 for n in nodes if len(n["planes"]) > 1),
            "mean_confidence": round(
                sum(n["confidence"] for n in nodes) / len(nodes), 4
            ) if nodes else 0.0,
            "unseen_anchors": [
                {
                    "id": n["id"], "name": n["name"],
                    "dependents": n["dependents"], "confidence": n["confidence"],
                }
                for n in unseen_anchors
            ],
        },
        "note": (
            "A projection of the scored estate, not a second risk model. Node "
            "colour is the risk level the QIRS engine already assigned; node size "
            "is the number of assets that transitively depend on it. Edges marked "
            "'observed' are read from certificate fields and scan locations; edges "
            "marked 'inferred' come from subsystem tags in the synthetic estate "
            "and would come from a CMDB on a real one."
        ),
    }
