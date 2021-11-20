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


class ConditionalInfoFlowAnalysisTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.p = compile_policy("tests/conditionalinfoflow.conf", mls=False)
        cls.m = PermissionMap("tests/perm_map")
        cls.a = InfoFlowAnalysis(cls.p, cls.m)

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.p.path)

    def test_001_keep_conditional_rules(self):
        """Keep all conditional rules."""
        self.a.booleans = None
        self.a._rebuildgraph = True
        self.a._build_subgraph()

        source = self.p.lookup_type("src")
        target = self.p.lookup_type("tgt")
        flow_true = self.p.lookup_type("flow_true")
        flow_false = self.p.lookup_type("flow_false")

        r = self.a.G.edges[source, flow_true]["rules"]
        self.assertEqual(len(r), 1)
        r = self.a.G.edges[flow_true, target]["rules"]
        self.assertEqual(len(r), 1)
        r = self.a.G.edges[source, flow_false]["rules"]
        self.assertEqual(len(r), 1)
        r = self.a.G.edges[flow_false, target]["rules"]
        self.assertEqual(len(r), 1)

    def test_002_default_conditional_rules(self):
        """Keep only default conditional rules."""
        self.a.booleans = {}
        self.a._rebuildgraph = True
        self.a._build_subgraph()

        source = self.p.lookup_type("src")
        target = self.p.lookup_type("tgt")
        flow_true = self.p.lookup_type("flow_true")
        flow_false = self.p.lookup_type("flow_false")

        r = self.a.G.edges[source, flow_true]["rules"]
        self.assertEqual(len(r), 0)
        r = self.a.G.edges[flow_true, target]["rules"]
        self.assertEqual(len(r), 0)
        r = self.a.G.edges[source, flow_false]["rules"]
        self.assertEqual(len(r), 1)
        r = self.a.G.edges[flow_false, target]["rules"]
        self.assertEqual(len(r), 1)

    def test_003_user_conditional_true(self):
        """Keep only conditional rules selected by user specified booleans (True Case.)"""
        self.a.booleans = {"condition": True}
        self.a.rebuildgraph = True
        self.a._build_subgraph()

        source = self.p.lookup_type("src")
        target = self.p.lookup_type("tgt")
        flow_true = self.p.lookup_type("flow_true")
        flow_false = self.p.lookup_type("flow_false")

        r = self.a.G.edges[source, flow_true]["rules"]
        self.assertEqual(len(r), 1)
        r = self.a.G.edges[flow_true, target]["rules"]
        self.assertEqual(len(r), 1)
        r = self.a.G.edges[source, flow_false]["rules"]
        self.assertEqual(len(r), 0)
        r = self.a.G.edges[flow_false, target]["rules"]
        self.assertEqual(len(r), 0)

    def test_004_user_conditional_false(self):
        """Keep only conditional rules selected by user specified booleans (False Case.)"""
        self.a.booleans = {"condition": False}
        self.a.rebuildgraph = True
        self.a._build_subgraph()

        source = self.p.lookup_type("src")
        target = self.p.lookup_type("tgt")
        flow_true = self.p.lookup_type("flow_true")
        flow_false = self.p.lookup_type("flow_false")

        r = self.a.G.edges[source, flow_true]["rules"]
        self.assertEqual(len(r), 0)
        r = self.a.G.edges[flow_true, target]["rules"]
        self.assertEqual(len(r), 0)
        r = self.a.G.edges[source, flow_false]["rules"]
        self.assertEqual(len(r), 1)
        r = self.a.G.edges[flow_false, target]["rules"]
        self.assertEqual(len(r), 1)

    def test_005_remaining_edges(self):
        """Keep edges when rules are deleted, but there are still remaining rules on the edge."""
        self.a.booleans = {}
        self.a.rebuildgraph = True
        self.a._build_subgraph()

        source = self.p.lookup_type("src_remain")
        target = self.p.lookup_type("tgt_remain")
        flow = self.p.lookup_type("flow_remain")

        r = self.a.G.edges[source, flow]["rules"]
        self.assertEqual(len(r), 1)
        self.assertEqual(str(r[0]), 'allow src_remain flow_remain:infoflow hi_w;')
        r = self.a.G.edges[flow, target]["rules"]
        self.assertEqual(len(r), 1)
        self.assertEqual(str(r[0]), 'allow tgt_remain flow_remain:infoflow hi_r;')
