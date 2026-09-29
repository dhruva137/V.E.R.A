"""The formal migration model - clusters, condensation, depth and order.

WHY THIS EXISTS
---------------
Ranking assets by risk answers "what is worst". It does not answer the question
a migration programme actually runs on: **in what order can these be moved, and
what must move together?**

That question has a published formalism - Loebenberger et al., *On the
Formalization of Cryptographic Migration* (arXiv:2408.05997) - and the paper
notes that building such a graph is "still a lot of manual work and is
currently not fully supported by tooling". This module implements it.

THE MODEL
---------
A migration graph G = (V, E) where an edge u -> v means **u depends on v**, so v
must be migrated before u can be.

  * **Migration cluster** - a strongly connected component of G. Components with
    mutual dependencies cannot be sequenced relative to each other, so they must
    migrate *simultaneously*. This is the single most useful output here: a
    cluster of nine assets is one change of nine parts, not nine changes.

  * **Migratable** - a cluster with no outgoing edges to other clusters. It
    depends on nothing still unmigrated, so it can go now. These are the only
    legitimate places to start.

  * **Condensation** G/c - the DAG formed by contracting each cluster to a
    node. Acyclic by construction, so it has a topological order.

  * **Canonical strategy** - a topological order of the condensation. Any valid
    migration sequence is one of these.

  * **Migration length** l(G) - the number of clusters. Every strategy traverses
    all of them, so this is a floor on the number of distinct changes.

  * **Migration depth** d(G) - the longest chain of dependent clusters. This is
    the floor on the number of *sequential* steps, and therefore on elapsed
    time no matter how much parallelism is available. It is the number a
    programme plan should be built around and the one nobody currently computes.

The paper's combinatorial analysis gives the asymptotics for random graphs
(expected steps ~ n/log n, expected cluster size ~ log n); those are reported
alongside the measured values so an operator can see whether their estate is
typical. They are a sanity check on the measurement, never a substitute for it.

Implementation is Tarjan's algorithm, iterative rather than recursive: a real
estate is deep enough to blow Python's stack, and a crashed scan on a large
customer is not an acceptable failure mode.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field


@dataclass
class Cluster:
    """A set of components that must migrate together."""

    id: int
    members: list[str]
    #: Cluster ids this cluster depends on. Empty means it can migrate now.
    depends_on: list[int] = field(default_factory=list)
    #: Cluster ids that depend on this one.
    required_by: list[int] = field(default_factory=list)
    #: Position in the canonical strategy, 1-based.
    order: int = 0
    #: Longest chain of dependencies below this cluster.
    depth: int = 0

    @property
    def size(self) -> int:
        return len(self.members)

    @property
    def migratable_now(self) -> bool:
        return not self.depends_on

    @property
    def is_entangled(self) -> bool:
        """More than one member means the parts cannot be sequenced apart."""
        return self.size > 1

    def to_dict(self, names: dict[str, str] | None = None) -> dict:
        names = names or {}
        return {
            "id": self.id,
            "size": self.size,
            "members": self.members,
            "member_names": [names.get(m, m) for m in self.members],
            "depends_on": self.depends_on,
            "required_by": self.required_by,
            "order": self.order,
            "depth": self.depth,
            "migratable_now": self.migratable_now,
            "entangled": self.is_entangled,
            "note": (
                f"{self.size} components with mutual dependencies: they cannot be "
                f"sequenced relative to each other, so this is one change of "
                f"{self.size} parts rather than {self.size} changes."
                if self.is_entangled else
                "A single component with no mutual dependencies."
            ),
        }


def _tarjan(nodes: list[str], edges: dict[str, set[str]]) -> list[list[str]]:
    """Strongly connected components, iteratively.

    Tarjan's algorithm without recursion. A real dependency graph is deep enough
    to exceed Python's recursion limit, and a crashed scan on a large estate is
    not an acceptable failure mode.
    """
    index_of: dict[str, int] = {}
    low: dict[str, int] = {}
    on_stack: dict[str, bool] = {}
    stack: list[str] = []
    result: list[list[str]] = []
    counter = 0

    for root in nodes:
        if root in index_of:
            continue

        # Each frame: (node, iterator over its successors)
        work: list[tuple[str, list[str]]] = [(root, sorted(edges.get(root, ())))]
        index_of[root] = low[root] = counter
        counter += 1
        stack.append(root)
        on_stack[root] = True

        while work:
            node, successors = work[-1]

            progressed = False
            while successors:
                succ = successors.pop(0)
                if succ not in index_of:
                    index_of[succ] = low[succ] = counter
                    counter += 1
                    stack.append(succ)
                    on_stack[succ] = True
                    work.append((succ, sorted(edges.get(succ, ()))))
                    progressed = True
                    break
                if on_stack.get(succ):
                    low[node] = min(low[node], index_of[succ])

            if progressed:
                continue

            work.pop()
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[node])

            if low[node] == index_of[node]:
                component = []
                while True:
                    member = stack.pop()
                    on_stack[member] = False
                    component.append(member)
                    if member == node:
                        break
                result.append(sorted(component))

    return result


def analyse(nodes: list[str], dependency_edges: list[tuple[str, str]],
            names: dict[str, str] | None = None) -> dict:
    """Build the migration graph and derive the canonical strategy.

    `dependency_edges` are (u, v) meaning **u depends on v**, so v migrates
    first. Edges to unknown nodes are dropped rather than silently creating
    phantom vertices, because a phantom would change the depth - the one number
    a programme plan is built on.
    """
    known = set(nodes)
    edges: dict[str, set[str]] = {n: set() for n in nodes}
    dropped = 0
    for source, target in dependency_edges:
        if source in known and target in known and source != target:
            edges[source].add(target)
        else:
            dropped += 1

    components = _tarjan(nodes, edges)
    cluster_of: dict[str, int] = {}
    clusters: list[Cluster] = []
    for index, members in enumerate(components):
        clusters.append(Cluster(id=index, members=members))
        for member in members:
            cluster_of[member] = index

    # Contract to the condensation DAG.
    for cluster in clusters:
        outgoing: set[int] = set()
        for member in cluster.members:
            for target in edges.get(member, ()):
                target_cluster = cluster_of[target]
                if target_cluster != cluster.id:
                    outgoing.add(target_cluster)
        cluster.depends_on = sorted(outgoing)
    for cluster in clusters:
        for dependency in cluster.depends_on:
            clusters[dependency].required_by.append(cluster.id)

    # Depth: longest chain of dependencies beneath each cluster. Computed
    # bottom-up over the DAG, so it is exact rather than sampled.
    order = _topological(clusters)
    for cluster_id in order:
        cluster = clusters[cluster_id]
        cluster.depth = (
            1 + max((clusters[d].depth for d in cluster.depends_on), default=0)
        )

    # The canonical strategy: dependencies first, then the biggest entangled
    # clusters, because those are the ones that need scheduling attention.
    strategy = sorted(order, key=lambda cid: (clusters[cid].depth, -clusters[cid].size))
    for position, cluster_id in enumerate(strategy, start=1):
        clusters[cluster_id].order = position

    n = max(len(nodes), 1)
    entangled = [c for c in clusters if c.is_entangled]
    migratable = [c for c in clusters if c.migratable_now]
    depth = max((c.depth for c in clusters), default=0)

    return {
        "components": len(nodes),
        "dependency_edges": sum(len(v) for v in edges.values()),
        "dropped_edges": dropped,
        "migration_length": len(clusters),
        "migration_depth": depth,
        "entangled_clusters": len(entangled),
        "largest_cluster": max((c.size for c in clusters), default=0),
        "migratable_now": len(migratable),
        "clusters": [
            clusters[cid].to_dict(names) for cid in strategy
        ],
        "start_here": [
            clusters[c.id].to_dict(names)
            for c in sorted(migratable, key=lambda c: -c.size)[:10]
        ],
        "expected": _expected_shape(n),
        "reading": _reading(len(clusters), depth, entangled, migratable, n),
    }


def _topological(clusters: list[Cluster]) -> list[int]:
    """Cluster ids, dependencies before dependents.

    Kahn's algorithm over the condensation. It is acyclic by construction, so a
    remaining-node count that does not reach zero would mean the SCC pass was
    wrong - asserted rather than assumed.
    """
    remaining = {c.id: len(c.depends_on) for c in clusters}
    ready = sorted(cid for cid, count in remaining.items() if count == 0)
    order: list[int] = []

    while ready:
        cluster_id = ready.pop(0)
        order.append(cluster_id)
        for dependent in sorted(clusters[cluster_id].required_by):
            remaining[dependent] -= 1
            if remaining[dependent] == 0:
                ready.append(dependent)
        ready.sort()

    if len(order) != len(clusters):
        raise AssertionError(
            "The condensation of a graph by its strongly connected components "
            "must be acyclic. A cycle here means the SCC pass is wrong."
        )
    return order


def _expected_shape(n: int) -> dict:
    """What the paper's asymptotics predict for a random graph of this size.

    Reported next to the measured values so an operator can see whether their
    estimate is typical or unusual. It is a comparison, never a substitute.
    """
    log_n = math.log(n) if n > 1 else 1.0
    return {
        "expected_migration_steps": round(n / log_n, 1) if log_n else 0.0,
        "expected_cluster_size": round(log_n, 2),
        "source": "Loebenberger et al., On the Formalization of Cryptographic Migration (arXiv:2408.05997)",
        "note": (
            "Asymptotics for a random graph of this size. A real estate is not "
            "random, so a large divergence is informative rather than an error."
        ),
    }


def _reading(length: int, depth: int, entangled: list, migratable: list, n: int) -> str:
    """One paragraph a programme manager can act on."""
    if not length:
        return "No components to migrate."

    parts = [
        f"{n} components resolve into {length} migration cluster(s). "
        f"Migration depth is {depth}: no schedule can complete in fewer than "
        f"{depth} sequential step(s), however much runs in parallel."
    ]
    if entangled:
        biggest = max(entangled, key=lambda c: c.size)
        parts.append(
            f"{len(entangled)} cluster(s) are entangled - their members depend on "
            f"each other and cannot be sequenced apart. The largest holds "
            f"{biggest.size} components and is one change of {biggest.size} parts, "
            f"not {biggest.size} changes."
        )
    if migratable:
        parts.append(
            f"{len(migratable)} cluster(s) depend on nothing unmigrated and can "
            f"start immediately."
        )
    else:
        parts.append(
            "No cluster is free of dependencies, which for a directed acyclic "
            "condensation is impossible and indicates a graph construction fault."
        )
    return " ".join(parts)
