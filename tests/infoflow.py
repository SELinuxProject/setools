# Copyright 2014-2015, Tresys Technology, LLC
#
# This file is part of SETools.
#
# SETools is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# SETools is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with SETools.  If not, see <http://www.gnu.org/licenses/>.
#
import unittest

import networkx as nx

from setools import SELinuxPolicy
from setools.infoflow import InfoFlowAnalysis
from setools.permmap import PermissionMap
from setools.policyrep.rule import RuleNotConditional
from setools.policyrep.typeattr import InvalidType


# Note: the testing for having correct rules on every edge is only
# performed once on the full graph, since it is assumed that NetworkX's
# Digraph.subgraph() function correctly copies the edge attributes into
# the subgraph.


class InfoFlowAnalysisTest(unittest.TestCase):

    @classmethod
    def setUpClass(self):
        self.p = SELinuxPolicy("tests/infoflow.conf")
        self.m = PermissionMap("tests/perm_map")

    def test_001_full_graph(self):
        """Information flow analysis full graph."""

        a = InfoFlowAnalysis(self.p, self.m)
        a._build_graph()

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

        nodes = set(a.G.nodes_iter())
        self.assertSetEqual(set([disconnected1, disconnected2, node1,
                                 node2, node3, node4, node5,
                                 node6, node7, node8, node9]), nodes)

        edges = set(a.G.out_edges_iter())
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

        r = a.G.edge[disconnected1][disconnected2]["rules"]
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0].ruletype, "allow")
        self.assertEqual(r[0].source, "disconnected1")
        self.assertEqual(r[0].target, "disconnected2")
        self.assertEqual(r[0].tclass, "infoflow2")
        self.assertSetEqual(set(["super"]), r[0].perms)
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

        r = a.G.edge[disconnected2][disconnected1]["rules"]
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0].ruletype, "allow")
        self.assertEqual(r[0].source, "disconnected1")
        self.assertEqual(r[0].target, "disconnected2")
        self.assertEqual(r[0].tclass, "infoflow2")
        self.assertSetEqual(set(["super"]), r[0].perms)
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

        r = sorted(a.G.edge[node1][node2]["rules"])
        self.assertEqual(len(r), 2)
        self.assertEqual(r[0].ruletype, "allow")
        self.assertEqual(r[0].source, "node1")
        self.assertEqual(r[0].target, "node2")
        self.assertEqual(r[0].tclass, "infoflow")
        self.assertSetEqual(set(["med_w"]), r[0].perms)
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

        self.assertEqual(r[1].ruletype, "allow")
        self.assertEqual(r[1].source, "node2")
        self.assertEqual(r[1].target, "node1")
        self.assertEqual(r[1].tclass, "infoflow")
        self.assertSetEqual(set(["hi_r"]), r[1].perms)
        self.assertRaises(RuleNotConditional, getattr, r[1], "conditional")

        r = sorted(a.G.edge[node1][node3]["rules"])
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0].ruletype, "allow")
        self.assertEqual(r[0].source, "node3")
        self.assertEqual(r[0].target, "node1")
        self.assertEqual(r[0].tclass, "infoflow")
        self.assertSetEqual(set(["low_r", "med_r"]), r[0].perms)
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

        r = sorted(a.G.edge[node2][node4]["rules"])
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0].ruletype, "allow")
        self.assertEqual(r[0].source, "node2")
        self.assertEqual(r[0].target, "node4")
        self.assertEqual(r[0].tclass, "infoflow")
        self.assertSetEqual(set(["hi_w"]), r[0].perms)
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

        r = sorted(a.G.edge[node3][node5]["rules"])
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0].ruletype, "allow")
        self.assertEqual(r[0].source, "node5")
        self.assertEqual(r[0].target, "node3")
        self.assertEqual(r[0].tclass, "infoflow")
        self.assertSetEqual(set(["low_r"]), r[0].perms)
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

        r = sorted(a.G.edge[node4][node6]["rules"])
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0].ruletype, "allow")
        self.assertEqual(r[0].source, "node4")
        self.assertEqual(r[0].target, "node6")
        self.assertEqual(r[0].tclass, "infoflow2")
        self.assertSetEqual(set(["hi_w"]), r[0].perms)
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

        r = sorted(a.G.edge[node5][node8]["rules"])
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0].ruletype, "allow")
        self.assertEqual(r[0].source, "node5")
        self.assertEqual(r[0].target, "node8")
        self.assertEqual(r[0].tclass, "infoflow2")
        self.assertSetEqual(set(["hi_w"]), r[0].perms)
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

        r = sorted(a.G.edge[node6][node5]["rules"])
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0].ruletype, "allow")
        self.assertEqual(r[0].source, "node5")
        self.assertEqual(r[0].target, "node6")
        self.assertEqual(r[0].tclass, "infoflow")
        self.assertSetEqual(set(["med_r"]), r[0].perms)
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

        r = sorted(a.G.edge[node6][node7]["rules"])
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0].ruletype, "allow")
        self.assertEqual(r[0].source, "node6")
        self.assertEqual(r[0].target, "node7")
        self.assertEqual(r[0].tclass, "infoflow")
        self.assertSetEqual(set(["hi_w"]), r[0].perms)
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

        r = sorted(a.G.edge[node8][node9]["rules"])
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0].ruletype, "allow")
        self.assertEqual(r[0].source, "node8")
        self.assertEqual(r[0].target, "node9")
        self.assertEqual(r[0].tclass, "infoflow2")
        self.assertSetEqual(set(["super"]), r[0].perms)
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

        r = sorted(a.G.edge[node9][node8]["rules"])
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0].ruletype, "allow")
        self.assertEqual(r[0].source, "node8")
        self.assertEqual(r[0].target, "node9")
        self.assertEqual(r[0].tclass, "infoflow2")
        self.assertSetEqual(set(["super"]), r[0].perms)
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

    def test_100_minimum_3(self):
        """Information flow analysis with minimum weight 3."""

        a = InfoFlowAnalysis(self.p, self.m, minweight=3)
        a._build_subgraph()

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

        # don't test nodes, as disconnected nodes
        # are not removed by subgraph generation
        # nodes = set(a.subG.nodes_iter())
        # self.assertSetEqual(set([disconnected1, disconnected2, node1,
        #                         node2, node3, node4, node5,
        #                         node6, node7, node8, node9]), nodes)

        edges = set(a.subG.out_edges_iter())
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

        a = InfoFlowAnalysis(self.p, self.m, minweight=8)
        a._build_subgraph()

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

        # don't test nodes, as disconnected nodes
        # are not removed by subgraph generation
        # nodes = set(a.subG.nodes_iter())
        # self.assertSetEqual(set([disconnected1, disconnected2, node1,
        #                         node2, node4, node5,
        #                         node6, node7, node8, node9]), nodes)

        edges = set(a.subG.out_edges_iter())
        self.assertSetEqual(set([(disconnected1, disconnected2),
                                 (disconnected2, disconnected1),
                                 (node1, node2),
                                 (node2, node4),
                                 (node4, node6),
                                 (node5, node8),
                                 (node6, node7),
                                 (node8, node9),
                                 (node9, node8)]), edges)

    def test_900_set_exclude_invalid_type(self):
        """Information flow analysis: set invalid excluded type."""
        a = InfoFlowAnalysis(self.p, self.m)
        self.assertRaises(InvalidType, a.set_exclude, ["node1", "invalid_type"])

    def test_901_set_small_min_weight(self):
        """Information flow analysis: set too small weight."""
        a = InfoFlowAnalysis(self.p, self.m)
        self.assertRaises(ValueError, a.set_min_weight, 0)
        self.assertRaises(ValueError, a.set_min_weight, -3)

    def test_902_set_large_min_weight(self):
        """Information flow analysis: set too big weight."""
        a = InfoFlowAnalysis(self.p, self.m)
        self.assertRaises(ValueError, a.set_min_weight, 11)
        self.assertRaises(ValueError, a.set_min_weight, 50)

    def test_910_all_paths_invalid_source(self):
        """Information flow analysis: all paths with invalid source type."""
        a = InfoFlowAnalysis(self.p, self.m)
        with self.assertRaises(InvalidType):
            paths = list(a.all_paths("invalid_type", "node1"))

    def test_911_all_paths_invalid_target(self):
        """Information flow analysis: all paths with invalid target type."""
        a = InfoFlowAnalysis(self.p, self.m)
        with self.assertRaises(InvalidType):
            paths = list(a.all_paths("node1", "invalid_type"))

    def test_912_all_paths_invalid_maxlen(self):
        """Information flow analysis: all paths with invalid max path length."""
        a = InfoFlowAnalysis(self.p, self.m)
        with self.assertRaises(ValueError):
            paths = list(a.all_paths("node1", "node2", maxlen=-2))

    def test_913_all_paths_source_excluded(self):
        """Information flow analysis: all paths with excluded source type."""
        a = InfoFlowAnalysis(self.p, self.m, exclude=["node1"])
        paths = list(a.all_paths("node1", "node2"))
        self.assertEqual(0, len(paths))

    def test_914_all_paths_target_excluded(self):
        """Information flow analysis: all paths with excluded target type."""
        a = InfoFlowAnalysis(self.p, self.m, exclude=["node2"])
        paths = list(a.all_paths("node1", "node2"))
        self.assertEqual(0, len(paths))

    def test_915_all_paths_source_disconnected(self):
        """Information flow analysis: all paths with disconnected source type."""
        a = InfoFlowAnalysis(self.p, self.m)
        paths = list(a.all_paths("disconnected1", "node2"))
        self.assertEqual(0, len(paths))

    def test_916_all_paths_target_disconnected(self):
        """Information flow analysis: all paths with disconnected target type."""
        a = InfoFlowAnalysis(self.p, self.m)
        paths = list(a.all_paths("node2", "disconnected1"))
        self.assertEqual(0, len(paths))

    def test_920_shortest_path_invalid_source(self):
        """Information flow analysis: shortest path with invalid source type."""
        a = InfoFlowAnalysis(self.p, self.m)
        with self.assertRaises(InvalidType):
            paths = list(a.shortest_path("invalid_type", "node1"))

    def test_921_shortest_path_invalid_target(self):
        """Information flow analysis: shortest path with invalid target type."""
        a = InfoFlowAnalysis(self.p, self.m)
        with self.assertRaises(InvalidType):
            paths = list(a.shortest_path("node1", "invalid_type"))

    def test_922_shortest_path_source_excluded(self):
        """Information flow analysis: shortest path with excluded source type."""
        a = InfoFlowAnalysis(self.p, self.m, exclude=["node1"])
        paths = list(a.shortest_path("node1", "node2"))
        self.assertEqual(0, len(paths))

    def test_923_shortest_path_target_excluded(self):
        """Information flow analysis: shortest path with excluded target type."""
        a = InfoFlowAnalysis(self.p, self.m, exclude=["node2"])
        paths = list(a.shortest_path("node1", "node2"))
        self.assertEqual(0, len(paths))

    def test_924_shortest_path_source_disconnected(self):
        """Information flow analysis: shortest path with disconnected source type."""
        a = InfoFlowAnalysis(self.p, self.m)
        paths = list(a.shortest_path("disconnected1", "node2"))
        self.assertEqual(0, len(paths))

    def test_925_shortest_path_target_disconnected(self):
        """Information flow analysis: shortest path with disconnected target type."""
        a = InfoFlowAnalysis(self.p, self.m)
        paths = list(a.shortest_path("node2", "disconnected1"))
        self.assertEqual(0, len(paths))

    def test_930_all_shortest_paths_invalid_source(self):
        """Information flow analysis: all shortest paths with invalid source type."""
        a = InfoFlowAnalysis(self.p, self.m)
        with self.assertRaises(InvalidType):
            paths = list(a.all_shortest_paths("invalid_type", "node1"))

    def test_931_all_shortest_paths_invalid_target(self):
        """Information flow analysis: all shortest paths with invalid target type."""
        a = InfoFlowAnalysis(self.p, self.m)
        with self.assertRaises(InvalidType):
            paths = list(a.all_shortest_paths("node1", "invalid_type"))

    def test_932_all_shortest_paths_source_excluded(self):
        """Information flow analysis: all shortest paths with excluded source type."""
        a = InfoFlowAnalysis(self.p, self.m, exclude=["node1"])
        paths = list(a.all_shortest_paths("node1", "node2"))
        self.assertEqual(0, len(paths))

    def test_933_all_shortest_paths_target_excluded(self):
        """Information flow analysis: all shortest paths with excluded target type."""
        a = InfoFlowAnalysis(self.p, self.m, exclude=["node2"])
        paths = list(a.all_shortest_paths("node1", "node2"))
        self.assertEqual(0, len(paths))

    def test_934_all_shortest_paths_source_disconnected(self):
        """Information flow analysis: all shortest paths with disconnected source type."""
        a = InfoFlowAnalysis(self.p, self.m)
        paths = list(a.all_shortest_paths("disconnected1", "node2"))
        self.assertEqual(0, len(paths))

    def test_935_all_shortest_paths_target_disconnected(self):
        """Information flow analysis: all shortest paths with disconnected target type."""
        a = InfoFlowAnalysis(self.p, self.m)
        paths = list(a.all_shortest_paths("node2", "disconnected1"))
        self.assertEqual(0, len(paths))

    def test_940_infoflows_invalid_source(self):
        """Information flow analysis: infoflows with invalid source type."""
        a = InfoFlowAnalysis(self.p, self.m)
        with self.assertRaises(InvalidType):
            paths = list(a.infoflows("invalid_type"))

    def test_941_infoflows_source_excluded(self):
        """Information flow analysis: infoflows with excluded source type."""
        a = InfoFlowAnalysis(self.p, self.m, exclude=["node1"])
        paths = list(a.infoflows("node1"))
        self.assertEqual(0, len(paths))

    def test_942_infoflows_source_disconnected(self):
        """Information flow analysis: infoflows with disconnected source type."""
        a = InfoFlowAnalysis(self.p, self.m, exclude=["disconnected2"])
        paths = list(a.infoflows("disconnected1"))
        self.assertEqual(0, len(paths))
