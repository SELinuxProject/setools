# Copyright 2014-2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: GPL-2.0-only
#
import collections
import typing

import pytest
import setools
from setools import TERuletype as TERT

from . import util


# Note: the testing for having correct rules on every edge is only
# performed once on the full graph, since it is assumed that NetworkX's
# Digraph.subgraph() function correctly copies the edge attributes into
# the subgraph.

@pytest.fixture
def analysis(compiled_policy: setools.SELinuxPolicy) -> setools.InfoFlowAnalysis:
    perm_map = setools.PermissionMap("tests/library/perm_map")
    ret = setools.InfoFlowAnalysis(compiled_policy, perm_map)
    ret._build_graph()
    return ret


@pytest.mark.obj_args("tests/library/infoflow.conf")
class TestInfoFlowAnalysis:

    def test_full_graph(self, analysis: setools.InfoFlowAnalysis) -> None:
        """Information flow analysis full graph."""

        disconnected1 = analysis.policy.lookup_type("disconnected1")
        disconnected2 = analysis.policy.lookup_type("disconnected2")
        node1 = analysis.policy.lookup_type("node1")
        node2 = analysis.policy.lookup_type("node2")
        node3 = analysis.policy.lookup_type("node3")
        node4 = analysis.policy.lookup_type("node4")
        node5 = analysis.policy.lookup_type("node5")
        node6 = analysis.policy.lookup_type("node6")
        node7 = analysis.policy.lookup_type("node7")
        node8 = analysis.policy.lookup_type("node8")
        node9 = analysis.policy.lookup_type("node9")

        nodes = set(analysis.G.nodes())
        assert set([disconnected1, disconnected2, node1, node2, node3, node4, node5, node6, node7,
                    node8, node9]) == nodes

        edges = set(analysis.G.out_edges())
        assert set([(disconnected1, disconnected2),
                    (disconnected2, disconnected1),
                    (node1, node2),
                    (node1, node3),
                    (node2, node4),
                    (node3, node5),
                    (node4, node6),
                    (node5, node8),
                    (node6, node5),
                    (node6, node7),
                    (node8, node9),
                    (node9, node8)]) == edges

        r = analysis.G.edges[disconnected1, disconnected2]["rules"]
        assert len(r) == 1
        util.validate_rule(r[0], TERT.allow, "disconnected1", "disconnected2", tclass="infoflow2",
                           perms=set(["super"]))

        r = analysis.G.edges[disconnected2, disconnected1]["rules"]
        assert len(r) == 1
        util.validate_rule(r[0], TERT.allow, "disconnected1", "disconnected2", tclass="infoflow2",
                           perms=set(["super"]))

        r = sorted(analysis.G.edges[node1, node2]["rules"])
        assert len(r) == 2
        util.validate_rule(r[0], TERT.allow, "node1", "node2", tclass="infoflow",
                           perms=set(["med_w"]))
        util.validate_rule(r[1], TERT.allow, "node2", "node1", tclass="infoflow",
                           perms=set(["hi_r"]))

        r = sorted(analysis.G.edges[node1, node3]["rules"])
        assert len(r) == 1
        util.validate_rule(r[0], TERT.allow, "node3", "node1", tclass="infoflow",
                           perms=set(["low_r", "med_r"]))

        r = sorted(analysis.G.edges[node2, node4]["rules"])
        assert len(r) == 1
        util.validate_rule(r[0], TERT.allow, "node2", "node4", tclass="infoflow",
                           perms=set(["hi_w"]))

        r = sorted(analysis.G.edges[node3, node5]["rules"])
        assert len(r) == 1
        util.validate_rule(r[0], TERT.allow, "node5", "node3", tclass="infoflow",
                           perms=set(["low_r"]))

        r = sorted(analysis.G.edges[node4, node6]["rules"])
        assert len(r) == 1
        util.validate_rule(r[0], TERT.allow, "node4", "node6", tclass="infoflow2",
                           perms=set(["hi_w"]))

        r = sorted(analysis.G.edges[node5, node8]["rules"])
        assert len(r) == 1
        util.validate_rule(r[0], TERT.allow, "node5", "node8", tclass="infoflow2",
                           perms=set(["hi_w"]))

        r = sorted(analysis.G.edges[node6, node5]["rules"])
        assert len(r) == 1
        util.validate_rule(r[0], TERT.allow, "node5", "node6", tclass="infoflow",
                           perms=set(["med_r"]))

        r = sorted(analysis.G.edges[node6, node7]["rules"])
        assert len(r) == 1
        util.validate_rule(r[0], TERT.allow, "node6", "node7", tclass="infoflow",
                           perms=set(["hi_w"]))

        r = sorted(analysis.G.edges[node8, node9]["rules"])
        assert len(r) == 1
        util.validate_rule(r[0], TERT.allow, "node8", "node9", tclass="infoflow2",
                           perms=set(["super"]))

        r = sorted(analysis.G.edges[node9, node8]["rules"])
        assert len(r) == 1
        util.validate_rule(r[0], TERT.allow, "node8", "node9", tclass="infoflow2",
                           perms=set(["super"]))

    def test_minimum_3(self, analysis: setools.InfoFlowAnalysis) -> None:
        """Information flow analysis with minimum weight 3."""

        analysis.exclude = []
        analysis.min_weight = 3
        analysis._build_subgraph()

        disconnected1 = analysis.policy.lookup_type("disconnected1")
        disconnected2 = analysis.policy.lookup_type("disconnected2")
        node1 = analysis.policy.lookup_type("node1")
        node2 = analysis.policy.lookup_type("node2")
        node3 = analysis.policy.lookup_type("node3")
        node4 = analysis.policy.lookup_type("node4")
        node5 = analysis.policy.lookup_type("node5")
        node6 = analysis.policy.lookup_type("node6")
        node7 = analysis.policy.lookup_type("node7")
        node8 = analysis.policy.lookup_type("node8")
        node9 = analysis.policy.lookup_type("node9")

        # don't test nodes list, as disconnected nodes
        # are not removed by subgraph generation. we
        # assume NetworkX copies into the subgraph
        # correctly.

        edges = set(analysis.subG.out_edges())
        assert set([(disconnected1, disconnected2),
                    (disconnected2, disconnected1),
                    (node1, node2),
                    (node1, node3),
                    (node2, node4),
                    (node4, node6),
                    (node5, node8),
                    (node6, node5),
                    (node6, node7),
                    (node8, node9),
                    (node9, node8)]) == edges

    def test_minimum_8(self, analysis: setools.InfoFlowAnalysis) -> None:
        """Information flow analysis with minimum weight 8."""

        analysis.exclude = []
        analysis.min_weight = 8
        analysis._build_subgraph()

        disconnected1 = analysis.policy.lookup_type("disconnected1")
        disconnected2 = analysis.policy.lookup_type("disconnected2")
        node1 = analysis.policy.lookup_type("node1")
        node2 = analysis.policy.lookup_type("node2")
        node4 = analysis.policy.lookup_type("node4")
        node5 = analysis.policy.lookup_type("node5")
        node6 = analysis.policy.lookup_type("node6")
        node7 = analysis.policy.lookup_type("node7")
        node8 = analysis.policy.lookup_type("node8")
        node9 = analysis.policy.lookup_type("node9")

        # don't test nodes list, as disconnected nodes
        # are not removed by subgraph generation. we
        # assume NetworkX copies into the subgraph
        # correctly.

        edges = set(analysis.subG.out_edges())
        assert set([(disconnected1, disconnected2),
                    (disconnected2, disconnected1),
                    (node1, node2),
                    (node2, node4),
                    (node4, node6),
                    (node5, node8),
                    (node6, node7),
                    (node8, node9),
                    (node9, node8)]) == edges

    def test_all_paths(self, analysis: setools.InfoFlowAnalysis) -> None:
        """Information flow analysis: all paths output"""
        analysis.exclude = []
        analysis.min_weight = 1
        analysis.source = "node1"
        analysis.target = "node4"
        analysis.mode = setools.InfoFlowAnalysis.Mode.AllPaths
        analysis.depth_limit = 3

        paths = list(typing.cast(collections.abc.Iterable[setools.InfoFlowPath],
                                 analysis.results()))
        assert 1 == len(paths)

        steps = list(paths[0])
        assert 2 == len(steps)

        step = steps[0]
        assert isinstance(step.source, setools.Type)
        assert isinstance(step.target, setools.Type)
        assert step.source == "node1"
        assert step.target == "node2"
        for r in steps[0].rules:
            assert TERT.allow == r.ruletype

        step = steps[1]
        assert isinstance(step.source, setools.Type)
        assert isinstance(step.target, setools.Type)
        assert step.source == "node2"
        assert step.target == "node4"
        for r in step.rules:
            assert TERT.allow == r.ruletype

    def test_all_shortest_paths(self, analysis: setools.InfoFlowAnalysis) -> None:
        """Information flow analysis: all shortest paths output"""
        analysis.exclude = []
        analysis.min_weight = 1
        analysis.source = "node1"
        analysis.target = "node4"
        analysis.mode = setools.InfoFlowAnalysis.Mode.ShortestPaths

        paths = list(typing.cast(collections.abc.Iterable[setools.InfoFlowPath],
                                 analysis.results()))
        assert 1 == len(paths)

        steps = list(paths[0])
        assert 2 == len(steps)

        step = steps[0]
        assert isinstance(step.source, setools.Type)
        assert isinstance(step.target, setools.Type)
        assert step.source == "node1"
        assert step.target == "node2"
        for r in steps[0].rules:
            assert TERT.allow == r.ruletype

        step = steps[1]
        assert isinstance(step.source, setools.Type)
        assert isinstance(step.target, setools.Type)
        assert step.source == "node2"
        assert step.target == "node4"
        for r in step.rules:
            assert TERT.allow == r.ruletype

    def test_infoflows_out(self, analysis: setools.InfoFlowAnalysis) -> None:
        """Information flow analysis: flows out of a type"""
        analysis.exclude = []
        analysis.min_weight = 1
        analysis.mode = setools.InfoFlowAnalysis.Mode.FlowsOut
        analysis.depth_limit = 1
        analysis.source = "node6"

        for flow in analysis.results():
            assert isinstance(flow, setools.InfoFlowStep)
            assert isinstance(flow.source, setools.Type)
            assert isinstance(flow.target, setools.Type)
            assert flow.source == "node6"
            for r in flow.rules:
                assert TERT.allow == r.ruletype

    def test_infoflows_in(self, analysis: setools.InfoFlowAnalysis) -> None:
        """Information flow analysis: flows in to a type"""
        analysis.exclude = []
        analysis.min_weight = 1
        analysis.mode = setools.InfoFlowAnalysis.Mode.FlowsIn
        analysis.depth_limit = 1
        analysis.target = "node8"

        for flow in analysis.results():
            assert isinstance(flow, setools.InfoFlowStep)
            assert isinstance(flow.source, setools.Type)
            assert isinstance(flow.target, setools.Type)
            assert flow.target == "node8"
            for r in flow.rules:
                assert TERT.allow == r.ruletype

    def test_set_exclude_invalid_type(self, analysis: setools.InfoFlowAnalysis) -> None:
        """Information flow analysis: set invalid excluded type."""
        with pytest.raises(setools.exception.InvalidType):
            analysis.exclude = ["node1", "invalid_type"]  # type: ignore[list-item]

    def test_set_small_min_weight(self, analysis: setools.InfoFlowAnalysis) -> None:
        """Information flow analysis: set too small weight."""

        with pytest.raises(ValueError):
            analysis.min_weight = 0

        with pytest.raises(ValueError):
            analysis.min_weight = -3

    def test_set_large_min_weight(self, analysis: setools.InfoFlowAnalysis) -> None:
        """Information flow analysis: set too big weight."""
        with pytest.raises(ValueError):
            analysis.min_weight = 11

        with pytest.raises(ValueError):
            analysis.min_weight = 50

    def test_invalid_source(self, analysis: setools.InfoFlowAnalysis) -> None:
        """Information flow analysis: invalid source type."""
        with pytest.raises(setools.exception.InvalidType):
            analysis.source = "invalid_type"

    def test_invalid_target(self, analysis: setools.InfoFlowAnalysis) -> None:
        """Information flow analysis: invalid target type."""
        with pytest.raises(setools.exception.InvalidType):
            analysis.target = "invalid_type"

    def test_all_paths_invalid_maxlen(self, analysis: setools.InfoFlowAnalysis) -> None:
        """Information flow analysis: all paths with invalid max path length."""
        analysis.exclude = []
        analysis.min_weight = 1
        analysis.mode = setools.InfoFlowAnalysis.Mode.AllPaths

        with pytest.raises(ValueError):
            analysis.depth_limit = -2

    def test_all_paths_source_excluded(self, analysis: setools.InfoFlowAnalysis) -> None:
        """Information flow analysis: all paths with excluded source type."""
        analysis.exclude = ["node1"]  # type: ignore[list-item]
        analysis.min_weight = 1
        analysis.mode = setools.InfoFlowAnalysis.Mode.AllPaths
        analysis.source = "node1"
        analysis.target = "node2"
        paths = list(analysis.results())
        assert 0 == len(paths)

    def test_all_paths_target_excluded(self, analysis: setools.InfoFlowAnalysis) -> None:
        """Information flow analysis: all paths with excluded target type."""
        analysis.exclude = ["node2"]  # type: ignore[list-item]
        analysis.min_weight = 1
        analysis.mode = setools.InfoFlowAnalysis.Mode.AllPaths
        analysis.source = "node1"
        analysis.target = "node2"
        paths = list(analysis.results())
        assert 0 == len(paths)

    def test_all_paths_source_disconnected(self, analysis: setools.InfoFlowAnalysis) -> None:
        """Information flow analysis: all paths with disconnected source type."""
        analysis.exclude = []
        analysis.min_weight = 1
        analysis.mode = setools.InfoFlowAnalysis.Mode.AllPaths
        analysis.source = "disconnected1"
        analysis.target = "node2"
        paths = list(analysis.results())
        assert 0 == len(paths)

    def test_all_paths_target_disconnected(self, analysis: setools.InfoFlowAnalysis) -> None:
        """Information flow analysis: all paths with disconnected target type."""
        analysis.exclude = []
        analysis.min_weight = 1
        analysis.source = "node2"
        analysis.target = "disconnected1"
        analysis.mode = setools.InfoFlowAnalysis.Mode.AllPaths
        paths = list(analysis.results())
        assert 0 == len(paths)

    def test_all_shortest_paths_source_excluded(self, analysis: setools.InfoFlowAnalysis) -> None:
        """Information flow analysis: all shortest paths with excluded source type."""
        analysis.exclude = ["node1"]  # type: ignore[list-item]
        analysis.min_weight = 1
        analysis.mode = setools.InfoFlowAnalysis.Mode.ShortestPaths
        analysis.source = "node1"
        analysis.target = "node2"
        paths = list(analysis.results())
        assert 0 == len(paths)

    def test_all_shortest_paths_target_excluded(self, analysis: setools.InfoFlowAnalysis) -> None:
        """Information flow analysis: all shortest paths with excluded target type."""
        analysis.exclude = ["node2"]  # type: ignore[list-item]
        analysis.min_weight = 1
        analysis.mode = setools.InfoFlowAnalysis.Mode.ShortestPaths
        analysis.source = "node1"
        analysis.target = "node2"
        paths = list(analysis.results())
        assert 0 == len(paths)

    def test_all_shortest_paths_source_disconnected(
            self, analysis: setools.InfoFlowAnalysis) -> None:
        """Information flow analysis: all shortest paths with disconnected source type."""
        analysis.exclude = []
        analysis.min_weight = 1
        analysis.mode = setools.InfoFlowAnalysis.Mode.ShortestPaths
        analysis.source = "disconnected1"
        analysis.target = "node2"
        paths = list(analysis.results())
        assert 0 == len(paths)

    def test_all_shortest_paths_target_disconnected(
            self, analysis: setools.InfoFlowAnalysis) -> None:
        """Information flow analysis: all shortest paths with disconnected target type."""
        analysis.exclude = []
        analysis.min_weight = 1
        analysis.source = "node2"
        analysis.target = "disconnected1"
        analysis.mode = setools.InfoFlowAnalysis.Mode.ShortestPaths
        paths = list(analysis.results())
        assert 0 == len(paths)

    def test_infoflows_source_excluded(self, analysis: setools.InfoFlowAnalysis) -> None:
        """Information flow analysis: infoflows with excluded source type."""
        analysis.exclude = ["node1"]  # type: ignore[list-item]
        analysis.min_weight = 1
        analysis.mode = setools.InfoFlowAnalysis.Mode.FlowsOut
        analysis.source = "node1"
        paths = list(analysis.results())
        assert 0 == len(paths)

    def test_infoflows_source_disconnected(self, analysis: setools.InfoFlowAnalysis) -> None:
        """Information flow analysis: infoflows with disconnected source type."""
        analysis.exclude = ["disconnected2"]  # type: ignore[list-item]
        analysis.min_weight = 1
        analysis.mode = setools.InfoFlowAnalysis.Mode.FlowsOut
        analysis.source = "disconnected1"
        paths = list(analysis.results())
        assert 0 == len(paths)
