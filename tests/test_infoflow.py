# Copyright 2014-2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: GPL-2.0-only
#
import os
import unittest

from setools import InfoFlowAnalysis
from setools import TERuletype as TERT
from setools.exception import InvalidType
from setools.permmap import PermissionMap
from setools.policyrep import Type

from . import mixins
from .policyrep.util import compile_policy


# Note: the testing for having correct rules on every edge is only
# performed once on the full graph, since it is assumed that NetworkX's
# Digraph.subgraph() function correctly copies the edge attributes into
# the subgraph.


class InfoFlowAnalysisTest(mixins.ValidateRule, unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.p = compile_policy("tests/infoflow.conf")
        cls.m = PermissionMap("tests/perm_map")
        cls.a = InfoFlowAnalysis(cls.p, cls.m)

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.p.path)

    def test_001_full_graph(self):
        """Information flow analysis full graph."""

        self.a._build_graph()

        disconnected1 = self.p.lookup_type("disconnected1")
        disconnected2 = self.p.lookup_type("disconnected2")
        node1 = self.p.lookup_type("node1")
        node2 = self.p.lookup_type("node2")
        node3 = self.p.lookup_type("node3")
        node4 = self.p.lookup_type("node4")
        node5 = self.p.lookup_type("node5")
        node6 = self.p.lookup_type("node6")
        node7 = self.p.lookup_type("node7")
        node8 = self.p.lookup_type("node8")
        node9 = self.p.lookup_type("node9")

        nodes = set(self.a.G.nodes())
        self.assertSetEqual(set([disconnected1, disconnected2, node1,
                                 node2, node3, node4, node5,
                                 node6, node7, node8, node9]), nodes)

        edges = set(self.a.G.out_edges())
        self.assertSetEqual(set([(disconnected1, disconnected2),
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
                                 (node9, node8)]), edges)

        r = self.a.G.edges[disconnected1, disconnected2]["rules"]
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], TERT.allow, "disconnected1", "disconnected2", "infoflow2",
                           set(["super"]))

        r = self.a.G.edges[disconnected2, disconnected1]["rules"]
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], TERT.allow, "disconnected1", "disconnected2", "infoflow2",
                           set(["super"]))

        r = sorted(self.a.G.edges[node1, node2]["rules"])
        self.assertEqual(len(r), 2)
        self.validate_rule(r[0], TERT.allow, "node1", "node2", "infoflow", set(["med_w"]))
        self.validate_rule(r[1], TERT.allow, "node2", "node1", "infoflow", set(["hi_r"]))

        r = sorted(self.a.G.edges[node1, node3]["rules"])
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], TERT.allow, "node3", "node1", "infoflow", set(["low_r", "med_r"]))

        r = sorted(self.a.G.edges[node2, node4]["rules"])
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], TERT.allow, "node2", "node4", "infoflow", set(["hi_w"]))

        r = sorted(self.a.G.edges[node3, node5]["rules"])
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], TERT.allow, "node5", "node3", "infoflow", set(["low_r"]))

        r = sorted(self.a.G.edges[node4, node6]["rules"])
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], TERT.allow, "node4", "node6", "infoflow2", set(["hi_w"]))

        r = sorted(self.a.G.edges[node5, node8]["rules"])
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], TERT.allow, "node5", "node8", "infoflow2", set(["hi_w"]))

        r = sorted(self.a.G.edges[node6, node5]["rules"])
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], TERT.allow, "node5", "node6", "infoflow", set(["med_r"]))

        r = sorted(self.a.G.edges[node6, node7]["rules"])
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], TERT.allow, "node6", "node7", "infoflow", set(["hi_w"]))

        r = sorted(self.a.G.edges[node8, node9]["rules"])
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], TERT.allow, "node8", "node9", "infoflow2", set(["super"]))

        r = sorted(self.a.G.edges[node9, node8]["rules"])
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], TERT.allow, "node8", "node9", "infoflow2", set(["super"]))

    def test_100_minimum_3(self):
        """Information flow analysis with minimum weight 3."""

        self.a.exclude = None
        self.a.min_weight = 3
        self.a._build_subgraph()

        disconnected1 = self.p.lookup_type("disconnected1")
        disconnected2 = self.p.lookup_type("disconnected2")
        node1 = self.p.lookup_type("node1")
        node2 = self.p.lookup_type("node2")
        node3 = self.p.lookup_type("node3")
        node4 = self.p.lookup_type("node4")
        node5 = self.p.lookup_type("node5")
        node6 = self.p.lookup_type("node6")
        node7 = self.p.lookup_type("node7")
        node8 = self.p.lookup_type("node8")
        node9 = self.p.lookup_type("node9")

        # don't test nodes list, as disconnected nodes
        # are not removed by subgraph generation. we
        # assume NetworkX copies into the subgraph
        # correctly.

        edges = set(self.a.subG.out_edges())
        self.assertSetEqual(set([(disconnected1, disconnected2),
                                 (disconnected2, disconnected1),
                                 (node1, node2),
                                 (node1, node3),
                                 (node2, node4),
                                 (node4, node6),
                                 (node5, node8),
                                 (node6, node5),
                                 (node6, node7),
                                 (node8, node9),
                                 (node9, node8)]), edges)

    def test_200_minimum_8(self):
        """Information flow analysis with minimum weight 8."""

        self.a.exclude = None
        self.a.min_weight = 8
        self.a._build_subgraph()

        disconnected1 = self.p.lookup_type("disconnected1")
        disconnected2 = self.p.lookup_type("disconnected2")
        node1 = self.p.lookup_type("node1")
        node2 = self.p.lookup_type("node2")
        node4 = self.p.lookup_type("node4")
        node5 = self.p.lookup_type("node5")
        node6 = self.p.lookup_type("node6")
        node7 = self.p.lookup_type("node7")
        node8 = self.p.lookup_type("node8")
        node9 = self.p.lookup_type("node9")

        # don't test nodes list, as disconnected nodes
        # are not removed by subgraph generation. we
        # assume NetworkX copies into the subgraph
        # correctly.

        edges = set(self.a.subG.out_edges())
        self.assertSetEqual(set([(disconnected1, disconnected2),
                                 (disconnected2, disconnected1),
                                 (node1, node2),
                                 (node2, node4),
                                 (node4, node6),
                                 (node5, node8),
                                 (node6, node7),
                                 (node8, node9),
                                 (node9, node8)]), edges)

    def test_300_all_paths(self):
        """Information flow analysis: all paths output"""
        self.a.exclude = None
        self.a.min_weight = 1
        self.a.source = "node1"
        self.a.target = "node4"
        self.a.mode = InfoFlowAnalysis.Mode.AllPaths
        self.a.depth_limit = 3

        paths = list(self.a.results())
        self.assertEqual(1, len(paths))

        steps = list(paths[0])
        self.assertEqual(2, len(steps))

        step = steps[0]
        self.assertIsInstance(step.source, Type)
        self.assertIsInstance(step.target, Type)
        self.assertEqual(step.source, "node1")
        self.assertEqual(step.target, "node2")
        for r in steps[0].rules:
            self.assertEqual(TERT.allow, r.ruletype)

        step = steps[1]
        self.assertIsInstance(step.source, Type)
        self.assertIsInstance(step.target, Type)
        self.assertEqual(step.source, "node2")
        self.assertEqual(step.target, "node4")
        for r in step.rules:
            self.assertEqual(TERT.allow, r.ruletype)

    def test_301_all_shortest_paths(self):
        """Information flow analysis: all shortest paths output"""
        self.a.exclude = None
        self.a.min_weight = 1
        self.a.source = "node1"
        self.a.target = "node4"
        self.a.mode = InfoFlowAnalysis.Mode.ShortestPaths

        paths = list(self.a.results())
        self.assertEqual(1, len(paths))

        steps = list(paths[0])
        self.assertEqual(2, len(steps))

        step = steps[0]
        self.assertIsInstance(step.source, Type)
        self.assertIsInstance(step.target, Type)
        self.assertEqual(step.source, "node1")
        self.assertEqual(step.target, "node2")
        for r in steps[0].rules:
            self.assertEqual(TERT.allow, r.ruletype)

        step = steps[1]
        self.assertIsInstance(step.source, Type)
        self.assertIsInstance(step.target, Type)
        self.assertEqual(step.source, "node2")
        self.assertEqual(step.target, "node4")
        for r in step.rules:
            self.assertEqual(TERT.allow, r.ruletype)

    def test_303_infoflows_out(self):
        """Information flow analysis: flows out of a type"""
        self.a.exclude = None
        self.a.min_weight = 1
        self.a.mode = InfoFlowAnalysis.Mode.FlowsOut
        self.a.depth_limit = 1
        self.a.source = "node6"

        for flow in self.a.results():
            self.assertIsInstance(flow.source, Type)
            self.assertIsInstance(flow.target, Type)
            self.assertEqual(flow.source, "node6")
            for r in flow.rules:
                self.assertEqual(TERT.allow, r.ruletype)

    def test_304_infoflows_in(self):
        """Information flow analysis: flows in to a type"""
        self.a.exclude = None
        self.a.min_weight = 1
        self.a.mode = InfoFlowAnalysis.Mode.FlowsIn
        self.a.depth_limit = 1
        self.a.target = "node8"

        for flow in self.a.results():
            self.assertIsInstance(flow.source, Type)
            self.assertIsInstance(flow.target, Type)
            self.assertEqual(flow.target, "node8")
            for r in flow.rules:
                self.assertEqual(TERT.allow, r.ruletype)

    def test_900_set_exclude_invalid_type(self):
        """Information flow analysis: set invalid excluded type."""
        with self.assertRaises(InvalidType):
            self.a.exclude = ["node1", "invalid_type"]

    def test_901_set_small_min_weight(self):
        """Information flow analysis: set too small weight."""

        with self.assertRaises(ValueError):
            self.a.min_weight = 0

        with self.assertRaises(ValueError):
            self.a.min_weight = -3

    def test_902_set_large_min_weight(self):
        """Information flow analysis: set too big weight."""
        with self.assertRaises(ValueError):
            self.a.min_weight = 11

        with self.assertRaises(ValueError):
            self.a.min_weight = 50

    def test_910_invalid_source(self):
        """Information flow analysis: invalid source type."""
        with self.assertRaises(InvalidType):
            self.a.source = "invalid_type"

    def test_911_invalid_target(self):
        """Information flow analysis: invalid target type."""
        with self.assertRaises(InvalidType):
            self.a.target = "invalid_type"

    def test_912_all_paths_invalid_maxlen(self):
        """Information flow analysis: all paths with invalid max path length."""
        self.a.exclude = None
        self.a.min_weight = 1
        self.a.mode = InfoFlowAnalysis.Mode.AllPaths

        with self.assertRaises(ValueError):
            self.a.depth_limit = -2

    def test_913_all_paths_source_excluded(self):
        """Information flow analysis: all paths with excluded source type."""
        self.a.exclude = ["node1"]
        self.a.min_weight = 1
        self.a.mode = InfoFlowAnalysis.Mode.AllPaths
        self.a.source = "node1"
        self.a.target = "node2"
        paths = list(self.a.results())
        self.assertEqual(0, len(paths))

    def test_914_all_paths_target_excluded(self):
        """Information flow analysis: all paths with excluded target type."""
        self.a.exclude = ["node2"]
        self.a.min_weight = 1
        self.a.mode = InfoFlowAnalysis.Mode.AllPaths
        self.a.source = "node1"
        self.a.target = "node2"
        paths = list(self.a.results())
        self.assertEqual(0, len(paths))

    def test_915_all_paths_source_disconnected(self):
        """Information flow analysis: all paths with disconnected source type."""
        self.a.exclude = None
        self.a.min_weight = 1
        self.a.mode = InfoFlowAnalysis.Mode.AllPaths
        self.a.source = "disconnected1"
        self.a.target = "node2"
        paths = list(self.a.results())
        self.assertEqual(0, len(paths))

    def test_916_all_paths_target_disconnected(self):
        """Information flow analysis: all paths with disconnected target type."""
        self.a.exclude = None
        self.a.min_weight = 1
        self.a.source = "node2"
        self.a.target = "disconnected1"
        self.a.mode = InfoFlowAnalysis.Mode.AllPaths
        paths = list(self.a.results())
        self.assertEqual(0, len(paths))

    def test_932_all_shortest_paths_source_excluded(self):
        """Information flow analysis: all shortest paths with excluded source type."""
        self.a.exclude = ["node1"]
        self.a.min_weight = 1
        self.a.mode = InfoFlowAnalysis.Mode.ShortestPaths
        self.a.source = "node1"
        self.a.target = "node2"
        paths = list(self.a.results())
        self.assertEqual(0, len(paths))

    def test_933_all_shortest_paths_target_excluded(self):
        """Information flow analysis: all shortest paths with excluded target type."""
        self.a.exclude = ["node2"]
        self.a.min_weight = 1
        self.a.mode = InfoFlowAnalysis.Mode.ShortestPaths
        self.a.source = "node1"
        self.a.target = "node2"
        paths = list(self.a.results())
        self.assertEqual(0, len(paths))

    def test_934_all_shortest_paths_source_disconnected(self):
        """Information flow analysis: all shortest paths with disconnected source type."""
        self.a.exclude = None
        self.a.min_weight = 1
        self.a.mode = InfoFlowAnalysis.Mode.ShortestPaths
        self.a.source = "disconnected1"
        self.a.target = "node2"
        paths = list(self.a.results())
        self.assertEqual(0, len(paths))

    def test_935_all_shortest_paths_target_disconnected(self):
        """Information flow analysis: all shortest paths with disconnected target type."""
        self.a.exclude = None
        self.a.min_weight = 1
        self.source = "node2"
        self.target = "disconnected1"
        self.a.mode = InfoFlowAnalysis.Mode.ShortestPaths
        paths = list(self.a.results())
        self.assertEqual(0, len(paths))

    def test_941_infoflows_source_excluded(self):
        """Information flow analysis: infoflows with excluded source type."""
        self.a.exclude = ["node1"]
        self.a.min_weight = 1
        self.a.mode = InfoFlowAnalysis.Mode.FlowsOut
        self.a.source = "node1"
        paths = list(self.a.results())
        self.assertEqual(0, len(paths))

    def test_942_infoflows_source_disconnected(self):
        """Information flow analysis: infoflows with disconnected source type."""
        self.a.exclude = ["disconnected2"]
        self.a.min_weight = 1
        self.a.mode = InfoFlowAnalysis.Mode.FlowsOut
        self.a.source = "disconnected1"
        paths = list(self.a.results())
        self.assertEqual(0, len(paths))
