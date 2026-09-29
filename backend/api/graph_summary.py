"""A per-asset projection of the dependency graph, without the graph.

WHY THIS EXISTS
---------------
The Inventory page needs four numbers per asset — how many things break if it
is rotated, how well observed it is, whether its sensors disagreed, and whether
that disagreement is a contradiction. The only endpoint that produced them was
`GET /api/dependencies`, which returns the whole projection: every node with its
scores, every edge, the edge-kind table and the stats block.

That is the right payload for drawing a graph and the wrong one for filling in
a column. `build_graph` emits roughly a kilobyte per node, so the full document
is ~196 KB for the bundled 195-asset estate and ~10 MB at the 10,000 the
product claims to handle — downloaded on every visit to a page that is supposed
to stay responsive at exactly that size.

This returns the same figures, computed by the same `build_graph` call, with
everything the caller did not ask for left out. Nothing is recomputed and no
second source of truth is introduced: if the graph and this ever disagreed, one
of them would be wrong, so they are the same function.

Lives in its own module rather than in `api/routes.py` to keep a very large
file from growing another concern.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

router = APIRouter()


@router.get("/dependencies/summary")
def dependency_summary():
    """Per-asset blast radius and evidence quality, keyed by asset id.

    Deliberately a dict rather than a list: every caller joins it onto assets it
    already holds, and making them build the index themselves invites two
    slightly different joins in two places.
    """
    from api.routes import state
    from engine.dependencies import build_graph

    if not state.assets:
        raise HTTPException(
            status_code=409,
            detail="No scan data available. Run a scan before asking for the graph.",
        )

    graph = build_graph(state.assets)
    nodes = graph.get("nodes", [])

    return {
        "count": len(nodes),
        "assets": {
            node["id"]: {
                "dependents": node.get("dependents", 0),
                "direct_dependents": node.get("direct_dependents", 0),
                "confidence": node.get("confidence"),
                "planes": node.get("planes", {}),
                "flagged": node.get("flagged", False),
            }
            for node in nodes
        },
        "stats": {
            # The few aggregates a summary reader actually wants, so the common
            # case never needs the full document at all.
            "max_dependents": graph.get("stats", {}).get("max_dependents", 0),
            "flagged_nodes": graph.get("stats", {}).get("flagged_nodes", 0),
            "disagreement_nodes": graph.get("stats", {}).get("disagreement_nodes", 0),
        },
        "note": (
            "A projection of GET /api/dependencies with the edges and per-node "
            "scores omitted. Same computation, same numbers — use the full "
            "endpoint when you need to draw the graph."
        ),
    }
