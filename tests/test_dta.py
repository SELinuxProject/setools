# Copyright 2014-2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: GPL-2.0-only
#
import os
import unittest

from setools import DomainTransitionAnalysis
from setools import TERuletype as TERT
from setools.exception import InvalidType
from setools.policyrep import Type

from . import mixins
from .policyrep.util import compile_policy


class DomainTransitionAnalysisTest(mixins.ValidateRule, unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.p = compile_policy("tests/dta.conf")
        cls.a = DomainTransitionAnalysis(cls.p)
        cls.a._build_graph()

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.p.path)

    def test_000_graph_structure(self):
        """DTA: verify graph structure."""
        # don't check node list since the disconnected nodes are not
        # removed after removing invalid domain transitions

        start = self.p.lookup_type("start")
        trans1 = self.p.lookup_type("trans1")
        trans2 = self.p.lookup_type("trans2")
        trans3 = self.p.lookup_type("trans3")
        trans5 = self.p.lookup_type("trans5")
        dyntrans100 = self.p.lookup_type("dyntrans100")
        bothtrans200 = self.p.lookup_type("bothtrans200")

        edges = set(self.a.G.out_edges())
        self.assertSetEqual(set([(dyntrans100, bothtrans200),
                                 (start, dyntrans100),
                                 (start, trans1),
                                 (trans1, trans2),
                                 (trans2, trans3),
                                 (trans3, trans5)]), edges)

    def test_001_bothtrans(self):
        """DTA: type_transition, setexeccon(), and setcon() transitions."""

        s = self.p.lookup_type("dyntrans100")
        t = self.p.lookup_type("bothtrans200")
        e = self.p.lookup_type("bothtrans200_exec")

        # regular transition
        r = self.a.G.edges[s, t]["transition"]
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], TERT.allow, s, t, "process", set(["transition", "dyntransition"]))

        # setexec perms
        r = self.a.G.edges[s, t]["setexec"]
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], TERT.allow, s, s, "process", set(["setexec", "setcurrent"]))

        # exec perms
        k = sorted(self.a.G.edges[s, t]["execute"].keys())
        self.assertEqual(k, [e])

        r = self.a.G.edges[s, t]["execute"][e]
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], TERT.allow, s, e, "file", set(["execute"]))

        # entrypoint perms
        k = sorted(self.a.G.edges[s, t]["entrypoint"].keys())
        self.assertEqual(k, [e])

        r = self.a.G.edges[s, t]["entrypoint"][e]
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], TERT.allow, t, e, "file", set(["entrypoint"]))

        # type_transition
        k = sorted(self.a.G.edges[s, t]["type_transition"].keys())
        self.assertEqual(k, [e])

        r = self.a.G.edges[s, t]["type_transition"][e]
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], TERT.type_transition, s, e, "process", t)

        # dynamic transition
        r = self.a.G.edges[s, t]["dyntransition"]
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], TERT.allow, s, t, "process", set(["transition", "dyntransition"]))

        # setcurrent
        r = self.a.G.edges[s, t]["setcurrent"]
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], TERT.allow, s, s, "process", set(["setexec", "setcurrent"]))

    def test_010_dyntrans(self):
        """DTA: setcon() transition."""

        s = self.p.lookup_type("start")
        t = self.p.lookup_type("dyntrans100")

        # regular transition
        r = self.a.G.edges[s, t]["transition"]
        self.assertEqual(len(r), 0)

        # setexec perms
        r = self.a.G.edges[s, t]["setexec"]
        self.assertEqual(len(r), 0)

        # exec perms
        k = sorted(self.a.G.edges[s, t]["execute"].keys())
        self.assertEqual(len(k), 0)

        # entrypoint perms
        k = sorted(self.a.G.edges[s, t]["entrypoint"].keys())
        self.assertEqual(len(k), 0)

        # type_transition
        k = sorted(self.a.G.edges[s, t]["type_transition"].keys())
        self.assertEqual(len(k), 0)

        # dynamic transition
        r = self.a.G.edges[s, t]["dyntransition"]
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], TERT.allow, s, t, "process", set(["dyntransition"]))

        # setcurrent
        r = self.a.G.edges[s, t]["setcurrent"]
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], TERT.allow, s, s, "process", set(["setcurrent"]))

    def test_020_trans(self):
        """DTA: type_transition transition."""

        s = self.p.lookup_type("start")
        t = self.p.lookup_type("trans1")
        e = self.p.lookup_type("trans1_exec")

        # regular transition
        r = self.a.G.edges[s, t]["transition"]
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], TERT.allow, s, t, "process", set(["transition"]))

        # setexec perms
        r = self.a.G.edges[s, t]["setexec"]
        self.assertEqual(len(r), 0)

        # exec perms
        k = sorted(self.a.G.edges[s, t]["execute"].keys())
        self.assertEqual(k, [e])

        r = self.a.G.edges[s, t]["execute"][e]
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], TERT.allow, s, e, "file", set(["execute"]))

        # entrypoint perms
        k = sorted(self.a.G.edges[s, t]["entrypoint"].keys())
        self.assertEqual(k, [e])

        r = self.a.G.edges[s, t]["entrypoint"][e]
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], TERT.allow, t, e, "file", set(["entrypoint"]))

        # type_transition
        k = sorted(self.a.G.edges[s, t]["type_transition"].keys())
        self.assertEqual(k, [e])

        r = self.a.G.edges[s, t]["type_transition"][e]
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], TERT.type_transition, s, e, "process", t)

        # dynamic transition
        r = self.a.G.edges[s, t]["dyntransition"]
        self.assertEqual(len(r), 0)

        # setcurrent
        r = self.a.G.edges[s, t]["setcurrent"]
        self.assertEqual(len(r), 0)

    def test_030_setexec(self):
        """DTA: setexec() transition."""

        s = self.p.lookup_type("trans1")
        t = self.p.lookup_type("trans2")
        e = self.p.lookup_type("trans2_exec")

        # regular transition
        r = self.a.G.edges[s, t]["transition"]
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], TERT.allow, s, t, "process", set(["transition"]))

        # setexec perms
        r = self.a.G.edges[s, t]["setexec"]
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], TERT.allow, s, s, "process", set(["setexec"]))

        # exec perms
        k = sorted(self.a.G.edges[s, t]["execute"].keys())
        self.assertEqual(k, [e])

        r = self.a.G.edges[s, t]["execute"][e]
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], TERT.allow, s, e, "file", set(["execute"]))

        # entrypoint perms
        k = sorted(self.a.G.edges[s, t]["entrypoint"].keys())
        self.assertEqual(k, [e])

        r = self.a.G.edges[s, t]["entrypoint"][e]
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], TERT.allow, t, e, "file", set(["entrypoint"]))

        # type_transition
        k = sorted(self.a.G.edges[s, t]["type_transition"].keys())
        self.assertEqual(len(k), 0)

        # dynamic transition
        r = self.a.G.edges[s, t]["dyntransition"]
        self.assertEqual(len(r), 0)

        # setcurrent
        r = self.a.G.edges[s, t]["setcurrent"]
        self.assertEqual(len(r), 0)

    def test_040_two_entrypoint(self):
        """DTA: 2 entrypoints, only one by type_transition."""

        s = self.p.lookup_type("trans2")
        t = self.p.lookup_type("trans3")
        e = [self.p.lookup_type("trans3_exec1"), self.p.lookup_type("trans3_exec2")]

        # regular transition
        r = self.a.G.edges[s, t]["transition"]
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], TERT.allow, s, t, "process", set(["transition"]))

        # setexec perms
        r = self.a.G.edges[s, t]["setexec"]
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], TERT.allow, s, s, "process", set(["setexec"]))

        # exec perms
        k = sorted(self.a.G.edges[s, t]["execute"].keys())
        self.assertEqual(k, e)

        r = self.a.G.edges[s, t]["execute"][e[0]]
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], TERT.allow, s, e[0], "file", set(["execute"]))

        r = self.a.G.edges[s, t]["execute"][e[1]]
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], TERT.allow, s, e[1], "file", set(["execute"]))

        # entrypoint perms
        k = sorted(self.a.G.edges[s, t]["entrypoint"].keys())
        self.assertEqual(k, e)

        r = self.a.G.edges[s, t]["entrypoint"][e[0]]
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], TERT.allow, t, e[0], "file", set(["entrypoint"]))

        r = self.a.G.edges[s, t]["entrypoint"][e[1]]
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], TERT.allow, t, e[1], "file", set(["entrypoint"]))

        # type_transition
        k = sorted(self.a.G.edges[s, t]["type_transition"].keys())
        self.assertEqual(k, [e[0]])

        r = self.a.G.edges[s, t]["type_transition"][e[0]]
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], TERT.type_transition, s, e[0], "process", t)

        # dynamic transition
        r = self.a.G.edges[s, t]["dyntransition"]
        self.assertEqual(len(r), 0)

        # setcurrent
        r = self.a.G.edges[s, t]["setcurrent"]
        self.assertEqual(len(r), 0)

    def test_050_cond_type_trans(self):
        """DTA: conditional type_transition."""

        s = self.p.lookup_type("trans3")
        t = self.p.lookup_type("trans5")
        e = self.p.lookup_type("trans5_exec")

        # regular transition
        r = self.a.G.edges[s, t]["transition"]
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], TERT.allow, s, t, "process", set(["transition"]))

        # setexec perms
        r = self.a.G.edges[s, t]["setexec"]
        self.assertEqual(len(r), 0)

        # exec perms
        k = sorted(self.a.G.edges[s, t]["execute"].keys())
        self.assertEqual(k, [e])

        r = self.a.G.edges[s, t]["execute"][e]
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], TERT.allow, s, e, "file", set(["execute"]))

        # entrypoint perms
        k = sorted(self.a.G.edges[s, t]["entrypoint"].keys())
        self.assertEqual(k, [e])

        r = self.a.G.edges[s, t]["entrypoint"][e]
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], TERT.allow, t, e, "file", set(["entrypoint"]))

        # type_transition
        k = sorted(self.a.G.edges[s, t]["type_transition"].keys())
        self.assertEqual(k, [e])

        r = self.a.G.edges[s, t]["type_transition"][e]
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], TERT.type_transition, s, e, "process", t, cond="trans5")

        # dynamic transition
        r = self.a.G.edges[s, t]["dyntransition"]
        self.assertEqual(len(r), 0)

        # setcurrent
        r = self.a.G.edges[s, t]["setcurrent"]
        self.assertEqual(len(r), 0)

    def test_100_forward_subgraph_structure(self):
        """DTA: verify forward subgraph structure."""
        # The purpose is to ensure the subgraph is reversed
        # only when the reverse option is set, not that
        # graph reversal is correct (assumed that NetworkX
        # does it correctly).
        # Don't check node list since the disconnected nodes are not
        # removed after removing invalid domain transitions

        self.a.reverse = False
        self.a._build_subgraph()

        start = self.p.lookup_type("start")
        trans1 = self.p.lookup_type("trans1")
        trans2 = self.p.lookup_type("trans2")
        trans3 = self.p.lookup_type("trans3")
        trans5 = self.p.lookup_type("trans5")
        dyntrans100 = self.p.lookup_type("dyntrans100")
        bothtrans200 = self.p.lookup_type("bothtrans200")

        edges = set(self.a.subG.out_edges())
        self.assertSetEqual(set([(dyntrans100, bothtrans200),
                                 (start, dyntrans100),
                                 (start, trans1),
                                 (trans1, trans2),
                                 (trans2, trans3),
                                 (trans3, trans5)]), edges)

    def test_101_reverse_subgraph_structure(self):
        """DTA: verify reverse subgraph structure."""
        # The purpose is to ensure the subgraph is reversed
        # only when the reverse option is set, not that
        # graph reversal is correct (assumed that NetworkX
        # does it correctly).
        # Don't check node list since the disconnected nodes are not
        # removed after removing invalid domain transitions

        self.a.reverse = True
        self.a._build_subgraph()

        start = self.p.lookup_type("start")
        trans1 = self.p.lookup_type("trans1")
        trans2 = self.p.lookup_type("trans2")
        trans3 = self.p.lookup_type("trans3")
        trans5 = self.p.lookup_type("trans5")
        dyntrans100 = self.p.lookup_type("dyntrans100")
        bothtrans200 = self.p.lookup_type("bothtrans200")

        edges = set(self.a.subG.out_edges())
        self.assertSetEqual(set([(bothtrans200, dyntrans100),
                                 (dyntrans100, start),
                                 (trans1, start),
                                 (trans2, trans1),
                                 (trans3, trans2),
                                 (trans5, trans3)]), edges)

    def test_200_exclude_domain(self):
        """DTA: exclude domain type."""
        # Don't check node list since the disconnected nodes are not
        # removed after removing invalid domain transitions

        self.a.reverse = False
        self.a.exclude = ["trans1"]
        self.a._build_subgraph()

        start = self.p.lookup_type("start")
        trans2 = self.p.lookup_type("trans2")
        trans3 = self.p.lookup_type("trans3")
        trans5 = self.p.lookup_type("trans5")
        dyntrans100 = self.p.lookup_type("dyntrans100")
        bothtrans200 = self.p.lookup_type("bothtrans200")

        edges = set(self.a.subG.out_edges())
        self.assertSetEqual(set([(dyntrans100, bothtrans200),
                                 (start, dyntrans100),
                                 (trans2, trans3),
                                 (trans3, trans5)]), edges)

    def test_201_exclude_entryoint_with_2entrypoints(self):
        """DTA: exclude entrypoint type without transition deletion (other entrypoints)."""
        # Don't check node list since the disconnected nodes are not
        # removed after removing invalid domain transitions

        self.a.reverse = False
        self.a.exclude = ["trans3_exec1"]
        self.a._build_subgraph()

        start = self.p.lookup_type("start")
        trans1 = self.p.lookup_type("trans1")
        trans2 = self.p.lookup_type("trans2")
        trans3 = self.p.lookup_type("trans3")
        trans5 = self.p.lookup_type("trans5")
        dyntrans100 = self.p.lookup_type("dyntrans100")
        bothtrans200 = self.p.lookup_type("bothtrans200")

        edges = set(self.a.subG.out_edges())
        self.assertSetEqual(set([(dyntrans100, bothtrans200),
                                 (start, dyntrans100),
                                 (start, trans1),
                                 (trans1, trans2),
                                 (trans2, trans3),
                                 (trans3, trans5)]), edges)

    def test_202_exclude_entryoint_with_dyntrans(self):
        """DTA: exclude entrypoint type without transition deletion (dyntrans)."""
        # Don't check node list since the disconnected nodes are not
        # removed after removing invalid domain transitions

        self.a.reverse = False
        self.a.exclude = ["bothtrans200_exec"]
        self.a._build_subgraph()

        start = self.p.lookup_type("start")
        trans1 = self.p.lookup_type("trans1")
        trans2 = self.p.lookup_type("trans2")
        trans3 = self.p.lookup_type("trans3")
        trans5 = self.p.lookup_type("trans5")
        dyntrans100 = self.p.lookup_type("dyntrans100")
        bothtrans200 = self.p.lookup_type("bothtrans200")

        edges = set(self.a.subG.out_edges())
        self.assertSetEqual(set([(dyntrans100, bothtrans200),
                                 (start, dyntrans100),
                                 (start, trans1),
                                 (trans1, trans2),
                                 (trans2, trans3),
                                 (trans3, trans5)]), edges)

    def test_203_exclude_entryoint_delete_transition(self):
        """DTA: exclude entrypoint type with transition deletion."""
        # Don't check node list since the disconnected nodes are not
        # removed after removing invalid domain transitions

        self.a.reverse = False
        self.a.exclude = ["trans2_exec"]
        self.a._build_subgraph()

        start = self.p.lookup_type("start")
        trans1 = self.p.lookup_type("trans1")
        trans2 = self.p.lookup_type("trans2")
        trans3 = self.p.lookup_type("trans3")
        trans5 = self.p.lookup_type("trans5")
        dyntrans100 = self.p.lookup_type("dyntrans100")
        bothtrans200 = self.p.lookup_type("bothtrans200")

        edges = set(self.a.subG.out_edges())
        self.assertSetEqual(set([(dyntrans100, bothtrans200),
                                 (start, dyntrans100),
                                 (start, trans1),
                                 (trans2, trans3),
                                 (trans3, trans5)]), edges)

    def test_300_all_paths(self):
        """DTA: all paths output"""
        self.a.reverse = False
        self.a.exclude = None
        self.a.source = "start"
        self.a.target = "bothtrans200"
        self.a.depth_limit = 3
        self.a.mode = DomainTransitionAnalysis.Mode.AllPaths

        expected_path = ["start", "dyntrans100", "bothtrans200"]

        paths = list(self.a.results())
        self.assertEqual(1, len(paths))

        for path in paths:
            for stepnum, step in enumerate(path):
                self.assertIsInstance(step.source, Type)
                self.assertIsInstance(step.target, Type)
                self.assertEqual(expected_path[stepnum], step.source)
                self.assertEqual(expected_path[stepnum + 1], step.target)

                for r in step.transition:
                    self.assertIn("transition", r.perms)

                for e in step.entrypoints:
                    self.assertIsInstance(e.name, Type)

                    for r in e.entrypoint:
                        self.assertIn("entrypoint", r.perms)

                    for r in e.execute:
                        self.assertIn("execute", r.perms)

                    for r in e.type_transition:
                        self.assertEqual(TERT.type_transition, r.ruletype)

                for r in step.setexec:
                    self.assertIn("setexec", r.perms)

                for r in step.dyntransition:
                    self.assertIn("dyntransition", r.perms)

                for r in step.setcurrent:
                    self.assertIn("setcurrent", r.perms)

    def test_301_all_shortest_paths(self):
        """DTA: all shortest paths output"""
        self.a.reverse = False
        self.a.exclude = None
        self.a.source = "start"
        self.a.target = "bothtrans200"
        self.a.mode = DomainTransitionAnalysis.Mode.ShortestPaths

        expected_path = ["start", "dyntrans100", "bothtrans200"]

        paths = list(self.a.results())
        self.assertEqual(1, len(paths))

        for path in paths:
            for stepnum, step in enumerate(path):
                self.assertIsInstance(step.source, Type)
                self.assertIsInstance(step.target, Type)
                self.assertEqual(expected_path[stepnum], step.source)
                self.assertEqual(expected_path[stepnum + 1], step.target)

                for r in step.transition:
                    self.assertIn("transition", r.perms)

                for e in step.entrypoints:
                    self.assertIsInstance(e.name, Type)

                    for r in e.entrypoint:
                        self.assertIn("entrypoint", r.perms)

                    for r in e.execute:
                        self.assertIn("execute", r.perms)

                    for r in e.type_transition:
                        self.assertEqual(TERT.type_transition, r.ruletype)

                for r in step.setexec:
                    self.assertIn("setexec", r.perms)

                for r in step.dyntransition:
                    self.assertIn("dyntransition", r.perms)

                for r in step.setcurrent:
                    self.assertIn("setcurrent", r.perms)

    def test_303_transitions(self):
        """DTA: transitions output"""
        self.a.reverse = False
        self.a.exclude = None
        self.a.source = "start"
        self.a.depth_limit = 1
        self.a.mode = DomainTransitionAnalysis.Mode.TransitionsOut

        transitions = list(self.a.results())
        self.assertEqual(2, len(transitions))

        for step in transitions:
            self.assertIsInstance(step.source, Type)
            self.assertIsInstance(step.target, Type)
            self.assertEqual("start", step.source)

            for r in step.transition:
                self.assertIn("transition", r.perms)

            for e in step.entrypoints:
                self.assertIsInstance(e.name, Type)

                for r in e.entrypoint:
                    self.assertIn("entrypoint", r.perms)

                for r in e.execute:
                    self.assertIn("execute", r.perms)

                for r in e.type_transition:
                    self.assertEqual(TERT.type_transition, r.ruletype)

            for r in step.setexec:
                self.assertIn("setexec", r.perms)

            for r in step.dyntransition:
                self.assertIn("dyntransition", r.perms)

            for r in step.setcurrent:
                self.assertIn("setcurrent", r.perms)

    def test_310_all_paths_reversed(self):
        """DTA: all paths output reverse DTA"""
        self.a.reverse = True
        self.a.exclude = None
        self.a.source = "bothtrans200"
        self.a.target = "start"
        self.a.depth_limit = 3
        self.a.mode = DomainTransitionAnalysis.Mode.AllPaths

        expected_path = ["bothtrans200", "dyntrans100", "start"]

        paths = list(self.a.results())
        self.assertEqual(1, len(paths))

        for path in paths:
            for stepnum, step in enumerate(path):
                self.assertIsInstance(step.source, Type)
                self.assertIsInstance(step.target, Type)
                self.assertEqual(step.source, expected_path[stepnum + 1])
                self.assertEqual(step.target, expected_path[stepnum])

                for r in step.transition:
                    self.assertIn("transition", r.perms)

                for e in step.entrypoints:
                    self.assertIsInstance(e.name, Type)

                    for r in e.entrypoint:
                        self.assertIn("entrypoint", r.perms)

                    for r in e.execute:
                        self.assertIn("execute", r.perms)

                    for r in e.type_transition:
                        self.assertEqual(TERT.type_transition, r.ruletype)

                for r in step.setexec:
                    self.assertIn("setexec", r.perms)

                for r in step.dyntransition:
                    self.assertIn("dyntransition", r.perms)

                for r in step.setcurrent:
                    self.assertIn("setcurrent", r.perms)

    def test_311_all_shortest_paths_reversed(self):
        """DTA: all shortest paths output reverse DTA"""
        self.a.reverse = True
        self.a.exclude = None
        self.a.source = "bothtrans200"
        self.a.target = "start"
        self.a.mode = DomainTransitionAnalysis.Mode.ShortestPaths

        expected_path = ["bothtrans200", "dyntrans100", "start"]

        paths = list(self.a.results())
        self.assertEqual(1, len(paths))

        for path in paths:
            for stepnum, step in enumerate(path):
                self.assertIsInstance(step.source, Type)
                self.assertIsInstance(step.target, Type)
                self.assertEqual(step.source, expected_path[stepnum + 1])
                self.assertEqual(step.target, expected_path[stepnum])

                for r in step.transition:
                    self.assertIn("transition", r.perms)

                for e in step.entrypoints:
                    self.assertIsInstance(e.name, Type)

                    for r in e.entrypoint:
                        self.assertIn("entrypoint", r.perms)

                    for r in e.execute:
                        self.assertIn("execute", r.perms)

                    for r in e.type_transition:
                        self.assertEqual(TERT.type_transition, r.ruletype)

                for r in step.setexec:
                    self.assertIn("setexec", r.perms)

                for r in step.dyntransition:
                    self.assertIn("dyntransition", r.perms)

                for r in step.setcurrent:
                    self.assertIn("setcurrent", r.perms)

    def test_313_transitions_reversed(self):
        """DTA: transitions output reverse DTA"""
        self.a.reverse = False
        self.a.exclude = None
        self.a.target = "bothtrans200"
        self.a.depth_limit = 1
        self.a.mode = DomainTransitionAnalysis.Mode.TransitionsIn

        transitions = list(self.a.results())
        self.assertEqual(1, len(transitions))

        for step in transitions:
            self.assertIsInstance(step.source, Type)
            self.assertIsInstance(step.target, Type)
            self.assertEqual("bothtrans200", step.target)

            for r in step.transition:
                self.assertIn("transition", r.perms)

            for e in step.entrypoints:
                self.assertIsInstance(e.name, Type)

                for r in e.entrypoint:
                    self.assertIn("entrypoint", r.perms)

                for r in e.execute:
                    self.assertIn("execute", r.perms)

                for r in e.type_transition:
                    self.assertEqual(TERT.type_transition, r.ruletype)

            for r in step.setexec:
                self.assertIn("setexec", r.perms)

            for r in step.dyntransition:
                self.assertIn("dyntransition", r.perms)

            for r in step.setcurrent:
                self.assertIn("setcurrent", r.perms)

    def test_900_set_exclude_invalid_type(self):
        """DTA: set invalid excluded type."""
        self.a.reverse = False
        self.a.exclude = None
        with self.assertRaises(InvalidType):
            self.a.exclude = ["trans1", "invalid_type"]

    def test_910_all_paths_invalid_source(self):
        """DTA: all paths with invalid source type."""
        self.a.reverse = False
        self.a.exclude = None
        self.a.mode = DomainTransitionAnalysis.Mode.AllPaths
        with self.assertRaises(InvalidType):
            self.a.source = "invalid_type"

    def test_911_all_paths_invalid_target(self):
        """DTA: all paths with invalid target type."""
        self.a.reverse = False
        self.a.exclude = None
        self.a.mode = DomainTransitionAnalysis.Mode.AllPaths
        with self.assertRaises(InvalidType):
            self.a.target = "invalid_type"

    def test_912_all_paths_invalid_maxlen(self):
        """DTA: all paths with invalid max path length."""
        self.a.reverse = False
        self.a.exclude = None
        self.a.mode = DomainTransitionAnalysis.Mode.AllPaths
        with self.assertRaises(ValueError):
            self.a.depth_limit = -2

    def test_913_all_paths_source_excluded(self):
        """DTA: all paths with excluded source type."""
        self.a.reverse = False
        self.a.exclude = ["trans1"]
        self.a.source = "trans1"
        self.a.target = "trans2"
        self.a.mode = DomainTransitionAnalysis.Mode.AllPaths
        paths = list(self.a.results())
        self.assertEqual(0, len(paths))

    def test_914_all_paths_target_excluded(self):
        """DTA: all paths with excluded target type."""
        self.a.reverse = False
        self.a.exclude = ["trans2"]
        self.a.source = "trans1"
        self.a.target = "trans2"
        self.a.mode = DomainTransitionAnalysis.Mode.AllPaths
        paths = list(self.a.results())
        self.assertEqual(0, len(paths))

    def test_915_all_paths_source_disconnected(self):
        """DTA: all paths with disconnected source type."""
        self.a.reverse = False
        self.a.exclude = None
        self.a.source = "trans5"
        self.a.target = "trans2"
        self.a.mode = DomainTransitionAnalysis.Mode.AllPaths
        paths = list(self.a.results())
        self.assertEqual(0, len(paths))

    def test_916_all_paths_target_disconnected(self):
        """DTA: all paths with disconnected target type."""
        self.a.reverse = False
        self.a.exclude = ["trans3"]
        self.a.source = "trans2"
        self.a.target = "trans5"
        self.a.mode = DomainTransitionAnalysis.Mode.AllPaths
        paths = list(self.a.results())
        self.assertEqual(0, len(paths))

    def test_925_shortest_path_target_disconnected(self):
        """DTA: shortest path with disconnected target type."""
        self.a.reverse = False
        self.a.exclude = ["trans3"]
        self.a.source = "trans2"
        self.a.target = "trans5"
        self.a.mode = DomainTransitionAnalysis.Mode.ShortestPaths
        paths = list(self.a.results())
        self.assertEqual(0, len(paths))

    def test_932_all_shortest_paths_source_excluded(self):
        """DTA: all shortest paths with excluded source type."""
        self.a.reverse = False
        self.a.exclude = ["trans1"]
        self.a.source = "trans1"
        self.a.target = "trans2"
        self.a.mode = DomainTransitionAnalysis.Mode.ShortestPaths
        paths = list(self.a.results())
        self.assertEqual(0, len(paths))

    def test_933_all_shortest_paths_target_excluded(self):
        """DTA: all shortest paths with excluded target type."""
        self.a.reverse = False
        self.a.exclude = ["trans2"]
        self.a.source = "trans1"
        self.a.target = "trans2"
        self.a.mode = DomainTransitionAnalysis.Mode.ShortestPaths
        paths = list(self.a.results())
        self.assertEqual(0, len(paths))

    def test_934_all_shortest_paths_source_disconnected(self):
        """DTA: all shortest paths with disconnected source type."""
        self.a.reverse = False
        self.a.exclude = None
        self.a.source = "trans5"
        self.a.target = "trans2"
        self.a.mode = DomainTransitionAnalysis.Mode.ShortestPaths
        paths = list(self.a.results())
        self.assertEqual(0, len(paths))

    def test_935_all_shortest_paths_target_disconnected(self):
        """DTA: all shortest paths with disconnected target type."""
        self.a.reverse = False
        self.a.exclude = ["trans3"]
        self.a.source = "trans2"
        self.a.target = "trans5"
        self.a.mode = DomainTransitionAnalysis.Mode.ShortestPaths
        paths = list(self.a.results())
        self.assertEqual(0, len(paths))

    def test_941_transitions_source_excluded(self):
        """DTA: transitions with excluded source type."""
        self.a.reverse = False
        self.a.exclude = ["trans1"]
        self.a.mode = DomainTransitionAnalysis.Mode.TransitionsOut
        self.a.source = "trans1"
        paths = list(self.a.results())
        self.assertEqual(0, len(paths))

    def test_942_transitions_source_disconnected(self):
        """DTA: transitions with disconnected source type."""
        self.a.reverse = False
        self.a.exclude = ["trans3"]
        self.a.source = "trans5"
        self.a.mode = DomainTransitionAnalysis.Mode.TransitionsOut
        paths = list(self.a.results())
        self.assertEqual(0, len(paths))
