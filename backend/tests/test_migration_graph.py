"""The formal migration model.

Implements Loebenberger et al., "On the Formalization of Cryptographic Migration"
(arXiv:2408.05997). The definitions are the paper's, so the tests check the
paper's properties rather than our output shape.

Edge convention throughout: (u, v) means u depends on v, so v migrates first.
"""

import pytest

from engine.core.migration_graph import Cluster, analyse


def test_a_chain_produces_one_cluster_per_link():
    """a -> b -> c: three separate changes, in a forced order."""
    r = analyse(["a", "b", "c"], [("a", "b"), ("b", "c")])
    assert r["migration_length"] == 3
    assert r["migration_depth"] == 3
    assert r["entangled_clusters"] == 0


def test_a_cycle_collapses_into_one_cluster():
    """Mutual dependency cannot be sequenced: it is one change of two parts."""
    r = analyse(["x", "y"], [("x", "y"), ("y", "x")])
    assert r["migration_length"] == 1
    assert r["largest_cluster"] == 2
    assert r["entangled_clusters"] == 1
    assert r["clusters"][0]["entangled"] is True


def test_only_dependency_free_clusters_can_start():
    """The paper's 'migratable': no outgoing edges to other clusters."""
    r = analyse(["a", "b", "c"], [("a", "b"), ("b", "c")])
    startable = {m for c in r["start_here"] for m in c["members"]}
    assert startable == {"c"}


def test_independent_components_can_all_start_at_once():
    r = analyse(["a", "b", "c"], [])
    assert r["migratable_now"] == 3
    assert r["migration_depth"] == 1


def test_depth_is_the_longest_chain_not_the_component_count():
    """Depth bounds elapsed time however much runs in parallel, so it must
    track the longest path, not the total work."""
    # Two parallel chains of 2, plus one isolated node.
    r = analyse(
        ["a1", "a2", "b1", "b2", "c"],
        [("a1", "a2"), ("b1", "b2")],
    )
    assert r["migration_length"] == 5
    assert r["migration_depth"] == 2


def test_a_diamond_has_depth_three():
    #   top -> left -> base,  top -> right -> base
    r = analyse(
        ["top", "left", "right", "base"],
        [("top", "left"), ("top", "right"), ("left", "base"), ("right", "base")],
    )
    assert r["migration_depth"] == 3
    assert {m for c in r["start_here"] for m in c["members"]} == {"base"}


def test_the_canonical_order_never_places_a_dependent_before_its_dependency():
    """The defining property of a valid strategy."""
    nodes = ["a", "b", "c", "d"]
    edges = [("a", "b"), ("b", "c"), ("d", "c")]
    r = analyse(nodes, edges)

    position = {}
    for cluster in r["clusters"]:
        for member in cluster["members"]:
            position[member] = cluster["order"]

    for dependent, dependency in edges:
        assert position[dependency] < position[dependent], (
            f"{dependent} was scheduled before its dependency {dependency}"
        )


def test_every_cluster_appears_exactly_once_in_the_strategy():
    r = analyse(list("abcdef"), [("a", "b"), ("c", "d"), ("e", "f")])
    ids = [c["id"] for c in r["clusters"]]
    orders = sorted(c["order"] for c in r["clusters"])
    assert len(ids) == len(set(ids))
    assert orders == list(range(1, len(ids) + 1))


def test_every_component_lands_in_exactly_one_cluster():
    """Conservation: nothing may be lost or duplicated by the SCC pass."""
    nodes = list("abcdefgh")
    r = analyse(nodes, [("a", "b"), ("b", "a"), ("c", "d"), ("e", "f"), ("f", "g")])
    members = [m for c in r["clusters"] for m in c["members"]]
    assert sorted(members) == sorted(nodes)


def test_edges_to_unknown_nodes_are_dropped_not_invented():
    """A phantom vertex would change the depth, which is the one number a
    programme plan is built on."""
    r = analyse(["a", "b"], [("a", "b"), ("a", "ghost"), ("ghost", "b")])
    assert r["dropped_edges"] == 2
    assert r["components"] == 2


def test_self_loops_do_not_create_a_false_cluster():
    r = analyse(["a", "b"], [("a", "a"), ("a", "b")])
    assert r["largest_cluster"] == 1
    assert r["entangled_clusters"] == 0


def test_an_empty_graph_is_handled():
    r = analyse([], [])
    assert r["migration_length"] == 0
    assert r["migration_depth"] == 0
    assert "No components" in r["reading"]


def test_a_deep_chain_does_not_blow_the_stack():
    """Tarjan is iterative for exactly this reason: a crashed scan on a large
    customer is not an acceptable failure mode."""
    n = 4000
    nodes = [f"n{i}" for i in range(n)]
    edges = [(f"n{i}", f"n{i+1}") for i in range(n - 1)]
    r = analyse(nodes, edges)
    assert r["migration_length"] == n
    assert r["migration_depth"] == n


def test_a_large_cycle_is_one_cluster():
    n = 500
    nodes = [f"n{i}" for i in range(n)]
    edges = [(f"n{i}", f"n{(i+1) % n}") for i in range(n)]
    r = analyse(nodes, edges)
    assert r["migration_length"] == 1
    assert r["largest_cluster"] == n


def test_theorem_one_expectations_are_reported_for_comparison():
    r = analyse(list("abcdefghij"), [])
    expected = r["expected"]
    assert expected["expected_migration_steps"] > 0
    assert "Loebenberger" in expected["source"]
    assert "not random" in expected["note"]


def test_the_reading_states_the_depth_bound():
    r = analyse(["a", "b", "c"], [("a", "b"), ("b", "c")])
    assert "sequential step" in r["reading"]
    assert "parallel" in r["reading"]


def test_an_entangled_cluster_explains_why_it_cannot_be_split():
    r = analyse(["x", "y", "z"], [("x", "y"), ("y", "z"), ("z", "x")])
    note = r["clusters"][0]["note"]
    assert "one change of 3 parts" in note
    assert "rather than 3 changes" in note


def test_cluster_dataclass_reports_migratability():
    assert Cluster(id=0, members=["a"]).migratable_now is True
    assert Cluster(id=1, members=["b"], depends_on=[0]).migratable_now is False
