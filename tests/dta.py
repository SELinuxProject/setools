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
from setools.dta import DomainTransitionAnalysis
from setools.policyrep.rule import RuleNotConditional


class InfoFlowAnalysisTest(unittest.TestCase):

    def setUp(self):
        self.p = SELinuxPolicy("tests/dta.conf")
        self.a = DomainTransitionAnalysis(self.p)
        self.a._build_graph()

    def test_000_graph_structure(self):
        """DTA: verify graph structure."""
        # don't check node list since the disconnected nodes are not
        # removed after removing invalid domain transitions

        start = self.p.lookup_type("start")
        trans1 = self.p.lookup_type("trans1")
        trans2 = self.p.lookup_type("trans2")
        trans3 = self.p.lookup_type("trans3")
        trans4 = self.p.lookup_type("trans4")
        trans5 = self.p.lookup_type("trans5")
        dyntrans100 = self.p.lookup_type("dyntrans100")
        bothtrans200 = self.p.lookup_type("bothtrans200")

        edges = set(self.a.G.out_edges_iter())
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
        r = self.a.G.edge[s][t]["transition"]
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0].ruletype, "allow")
        self.assertEqual(r[0].source, s)
        self.assertEqual(r[0].target, t)
        self.assertEqual(r[0].tclass, "process")
        self.assertSetEqual(set(["transition", "dyntransition"]), r[0].perms)
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

        # setexec perms
        r = self.a.G.edge[s][t]["setexec"]
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0].ruletype, "allow")
        self.assertEqual(r[0].source, s)
        self.assertEqual(r[0].target, s)
        self.assertEqual(r[0].tclass, "process")
        self.assertSetEqual(set(["setexec", "setcurrent"]), r[0].perms)
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

        # exec perms
        k = sorted(self.a.G.edge[s][t]["execute"].keys())
        self.assertEqual(k, [e])

        r = self.a.G.edge[s][t]["execute"][e]
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0].ruletype, "allow")
        self.assertEqual(r[0].source, s)
        self.assertEqual(r[0].target, e)
        self.assertEqual(r[0].tclass, "file")
        self.assertSetEqual(set(["execute"]), r[0].perms)
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

        # entrypoint perms
        k = sorted(self.a.G.edge[s][t]["entrypoint"].keys())
        self.assertEqual(k, [e])

        r = self.a.G.edge[s][t]["entrypoint"][e]
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0].ruletype, "allow")
        self.assertEqual(r[0].source, t)
        self.assertEqual(r[0].target, e)
        self.assertEqual(r[0].tclass, "file")
        self.assertSetEqual(set(["entrypoint"]), r[0].perms)
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

        # type_transition
        k = sorted(self.a.G.edge[s][t]["type_transition"].keys())
        self.assertEqual(k, [e])

        r = self.a.G.edge[s][t]["type_transition"][e]
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0].ruletype, "type_transition")
        self.assertEqual(r[0].source, s)
        self.assertEqual(r[0].target, e)
        self.assertEqual(r[0].tclass, "process")
        self.assertEqual(r[0].default, t)
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

        # dynamic transition
        r = self.a.G.edge[s][t]["dyntransition"]
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0].ruletype, "allow")
        self.assertEqual(r[0].source, s)
        self.assertEqual(r[0].target, t)
        self.assertEqual(r[0].tclass, "process")
        self.assertSetEqual(set(["transition", "dyntransition"]), r[0].perms)
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

        # setcurrent
        r = self.a.G.edge[s][t]["setcurrent"]
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0].ruletype, "allow")
        self.assertEqual(r[0].source, s)
        self.assertEqual(r[0].target, s)
        self.assertEqual(r[0].tclass, "process")
        self.assertSetEqual(set(["setexec", "setcurrent"]), r[0].perms)
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

    def test_010_dyntrans(self):
        """DTA: setcon() transition."""

        s = self.p.lookup_type("start")
        t = self.p.lookup_type("dyntrans100")

        # regular transition
        r = self.a.G.edge[s][t]["transition"]
        self.assertEqual(len(r), 0)

        # setexec perms
        r = self.a.G.edge[s][t]["setexec"]
        self.assertEqual(len(r), 0)

        # exec perms
        k = sorted(self.a.G.edge[s][t]["execute"].keys())
        self.assertEqual(len(k), 0)

        # entrypoint perms
        k = sorted(self.a.G.edge[s][t]["entrypoint"].keys())
        self.assertEqual(len(k), 0)

        # type_transition
        k = sorted(self.a.G.edge[s][t]["type_transition"].keys())
        self.assertEqual(len(k), 0)

        # dynamic transition
        r = self.a.G.edge[s][t]["dyntransition"]
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0].ruletype, "allow")
        self.assertEqual(r[0].source, s)
        self.assertEqual(r[0].target, t)
        self.assertEqual(r[0].tclass, "process")
        self.assertSetEqual(set(["dyntransition"]), r[0].perms)
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

        # setcurrent
        r = self.a.G.edge[s][t]["setcurrent"]
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0].ruletype, "allow")
        self.assertEqual(r[0].source, s)
        self.assertEqual(r[0].target, s)
        self.assertEqual(r[0].tclass, "process")
        self.assertSetEqual(set(["setcurrent"]), r[0].perms)
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

    def test_020_trans(self):
        """DTA: type_transition transition."""

        s = self.p.lookup_type("start")
        t = self.p.lookup_type("trans1")
        e = self.p.lookup_type("trans1_exec")

        # regular transition
        r = self.a.G.edge[s][t]["transition"]
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0].ruletype, "allow")
        self.assertEqual(r[0].source, s)
        self.assertEqual(r[0].target, t)
        self.assertEqual(r[0].tclass, "process")
        self.assertSetEqual(set(["transition"]), r[0].perms)
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

        # setexec perms
        r = self.a.G.edge[s][t]["setexec"]
        self.assertEqual(len(r), 0)

        # exec perms
        k = sorted(self.a.G.edge[s][t]["execute"].keys())
        self.assertEqual(k, [e])

        r = self.a.G.edge[s][t]["execute"][e]
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0].ruletype, "allow")
        self.assertEqual(r[0].source, s)
        self.assertEqual(r[0].target, e)
        self.assertEqual(r[0].tclass, "file")
        self.assertSetEqual(set(["execute"]), r[0].perms)
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

        # entrypoint perms
        k = sorted(self.a.G.edge[s][t]["entrypoint"].keys())
        self.assertEqual(k, [e])

        r = self.a.G.edge[s][t]["entrypoint"][e]
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0].ruletype, "allow")
        self.assertEqual(r[0].source, t)
        self.assertEqual(r[0].target, e)
        self.assertEqual(r[0].tclass, "file")
        self.assertSetEqual(set(["entrypoint"]), r[0].perms)
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

        # type_transition
        k = sorted(self.a.G.edge[s][t]["type_transition"].keys())
        self.assertEqual(k, [e])

        r = self.a.G.edge[s][t]["type_transition"][e]
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0].ruletype, "type_transition")
        self.assertEqual(r[0].source, s)
        self.assertEqual(r[0].target, e)
        self.assertEqual(r[0].tclass, "process")
        self.assertEqual(r[0].default, t)
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

        # dynamic transition
        r = self.a.G.edge[s][t]["dyntransition"]
        self.assertEqual(len(r), 0)

        # setcurrent
        r = self.a.G.edge[s][t]["setcurrent"]
        self.assertEqual(len(r), 0)

    def test_030_setexec(self):
        """DTA: setexec() transition."""

        s = self.p.lookup_type("trans1")
        t = self.p.lookup_type("trans2")
        e = self.p.lookup_type("trans2_exec")

        # regular transition
        r = self.a.G.edge[s][t]["transition"]
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0].ruletype, "allow")
        self.assertEqual(r[0].source, s)
        self.assertEqual(r[0].target, t)
        self.assertEqual(r[0].tclass, "process")
        self.assertSetEqual(set(["transition"]), r[0].perms)
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

        # setexec perms
        r = self.a.G.edge[s][t]["setexec"]
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0].ruletype, "allow")
        self.assertEqual(r[0].source, s)
        self.assertEqual(r[0].target, s)
        self.assertEqual(r[0].tclass, "process")
        self.assertSetEqual(set(["setexec"]), r[0].perms)
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

        # exec perms
        k = sorted(self.a.G.edge[s][t]["execute"].keys())
        self.assertEqual(k, [e])

        r = self.a.G.edge[s][t]["execute"][e]
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0].ruletype, "allow")
        self.assertEqual(r[0].source, s)
        self.assertEqual(r[0].target, e)
        self.assertEqual(r[0].tclass, "file")
        self.assertSetEqual(set(["execute"]), r[0].perms)
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

        # entrypoint perms
        k = sorted(self.a.G.edge[s][t]["entrypoint"].keys())
        self.assertEqual(k, [e])

        r = self.a.G.edge[s][t]["entrypoint"][e]
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0].ruletype, "allow")
        self.assertEqual(r[0].source, t)
        self.assertEqual(r[0].target, e)
        self.assertEqual(r[0].tclass, "file")
        self.assertSetEqual(set(["entrypoint"]), r[0].perms)
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

        # type_transition
        k = sorted(self.a.G.edge[s][t]["type_transition"].keys())
        self.assertEqual(len(k), 0)

        # dynamic transition
        r = self.a.G.edge[s][t]["dyntransition"]
        self.assertEqual(len(r), 0)

        # setcurrent
        r = self.a.G.edge[s][t]["setcurrent"]
        self.assertEqual(len(r), 0)

    def test_040_two_entrypoint(self):
        """DTA: 2 entrypoints, only one by type_transition."""

        s = self.p.lookup_type("trans2")
        t = self.p.lookup_type("trans3")
        e = [self.p.lookup_type("trans3_exec1"), self.p.lookup_type("trans3_exec2")]

        # regular transition
        r = self.a.G.edge[s][t]["transition"]
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0].ruletype, "allow")
        self.assertEqual(r[0].source, s)
        self.assertEqual(r[0].target, t)
        self.assertEqual(r[0].tclass, "process")
        self.assertSetEqual(set(["transition"]), r[0].perms)
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

        # setexec perms
        r = self.a.G.edge[s][t]["setexec"]
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0].ruletype, "allow")
        self.assertEqual(r[0].source, s)
        self.assertEqual(r[0].target, s)
        self.assertEqual(r[0].tclass, "process")
        self.assertSetEqual(set(["setexec"]), r[0].perms)
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

        # exec perms
        k = sorted(self.a.G.edge[s][t]["execute"].keys())
        self.assertEqual(k, e)

        r = self.a.G.edge[s][t]["execute"][e[0]]
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0].ruletype, "allow")
        self.assertEqual(r[0].source, s)
        self.assertEqual(r[0].target, e[0])
        self.assertEqual(r[0].tclass, "file")
        self.assertSetEqual(set(["execute"]), r[0].perms)
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

        r = self.a.G.edge[s][t]["execute"][e[1]]
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0].ruletype, "allow")
        self.assertEqual(r[0].source, s)
        self.assertEqual(r[0].target, e[1])
        self.assertEqual(r[0].tclass, "file")
        self.assertSetEqual(set(["execute"]), r[0].perms)
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

        # entrypoint perms
        k = sorted(self.a.G.edge[s][t]["entrypoint"].keys())
        self.assertEqual(k, e)

        r = self.a.G.edge[s][t]["entrypoint"][e[0]]
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0].ruletype, "allow")
        self.assertEqual(r[0].source, t)
        self.assertEqual(r[0].target, e[0])
        self.assertEqual(r[0].tclass, "file")
        self.assertSetEqual(set(["entrypoint"]), r[0].perms)
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

        r = self.a.G.edge[s][t]["entrypoint"][e[1]]
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0].ruletype, "allow")
        self.assertEqual(r[0].source, t)
        self.assertEqual(r[0].target, e[1])
        self.assertEqual(r[0].tclass, "file")
        self.assertSetEqual(set(["entrypoint"]), r[0].perms)
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

        # type_transition
        k = sorted(self.a.G.edge[s][t]["type_transition"].keys())
        self.assertEqual(k, [e[0]])

        r = self.a.G.edge[s][t]["type_transition"][e[0]]
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0].ruletype, "type_transition")
        self.assertEqual(r[0].source, s)
        self.assertEqual(r[0].target, e[0])
        self.assertEqual(r[0].tclass, "process")
        self.assertEqual(r[0].default, t)
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

        # dynamic transition
        r = self.a.G.edge[s][t]["dyntransition"]
        self.assertEqual(len(r), 0)

        # setcurrent
        r = self.a.G.edge[s][t]["setcurrent"]
        self.assertEqual(len(r), 0)

    def test_050_cond_type_trans(self):
        """DTA: conditional type_transition."""

        s = self.p.lookup_type("trans3")
        t = self.p.lookup_type("trans5")
        e = self.p.lookup_type("trans5_exec")

        # regular transition
        r = self.a.G.edge[s][t]["transition"]
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0].ruletype, "allow")
        self.assertEqual(r[0].source, s)
        self.assertEqual(r[0].target, t)
        self.assertEqual(r[0].tclass, "process")
        self.assertSetEqual(set(["transition"]), r[0].perms)
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

        # setexec perms
        r = self.a.G.edge[s][t]["setexec"]
        self.assertEqual(len(r), 0)

        # exec perms
        k = sorted(self.a.G.edge[s][t]["execute"].keys())
        self.assertEqual(k, [e])

        r = self.a.G.edge[s][t]["execute"][e]
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0].ruletype, "allow")
        self.assertEqual(r[0].source, s)
        self.assertEqual(r[0].target, e)
        self.assertEqual(r[0].tclass, "file")
        self.assertSetEqual(set(["execute"]), r[0].perms)
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

        # entrypoint perms
        k = sorted(self.a.G.edge[s][t]["entrypoint"].keys())
        self.assertEqual(k, [e])

        r = self.a.G.edge[s][t]["entrypoint"][e]
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0].ruletype, "allow")
        self.assertEqual(r[0].source, t)
        self.assertEqual(r[0].target, e)
        self.assertEqual(r[0].tclass, "file")
        self.assertSetEqual(set(["entrypoint"]), r[0].perms)
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

        # type_transition
        k = sorted(self.a.G.edge[s][t]["type_transition"].keys())
        self.assertEqual(k, [e])

        r = self.a.G.edge[s][t]["type_transition"][e]
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0].ruletype, "type_transition")
        self.assertEqual(r[0].source, s)
        self.assertEqual(r[0].target, e)
        self.assertEqual(r[0].tclass, "process")
        self.assertEqual(r[0].default, t)
        self.assertEqual(r[0].conditional, "trans5")

        # dynamic transition
        r = self.a.G.edge[s][t]["dyntransition"]
        self.assertEqual(len(r), 0)

        # setcurrent
        r = self.a.G.edge[s][t]["setcurrent"]
        self.assertEqual(len(r), 0)

    def test_100_forward_subgraph_structure(self):
        """DTA: verify forward subgraph structure."""
        # The purpose is to ensure the subgraph is reversed
        # only when the reverse option is set, not that
        # graph reversal is correct (assumed that NetworkX
        # does it correctly).
        # Don't check node list since the disconnected nodes are not
        # removed after removing invalid domain transitions

        self.a.set_reverse(False)
        self.a._build_subgraph()

        start = self.p.lookup_type("start")
        trans1 = self.p.lookup_type("trans1")
        trans2 = self.p.lookup_type("trans2")
        trans3 = self.p.lookup_type("trans3")
        trans4 = self.p.lookup_type("trans4")
        trans5 = self.p.lookup_type("trans5")
        dyntrans100 = self.p.lookup_type("dyntrans100")
        bothtrans200 = self.p.lookup_type("bothtrans200")

        edges = set(self.a.subG.out_edges_iter())
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

        self.a.set_reverse(True)
        self.a._build_subgraph()

        start = self.p.lookup_type("start")
        trans1 = self.p.lookup_type("trans1")
        trans2 = self.p.lookup_type("trans2")
        trans3 = self.p.lookup_type("trans3")
        trans4 = self.p.lookup_type("trans4")
        trans5 = self.p.lookup_type("trans5")
        dyntrans100 = self.p.lookup_type("dyntrans100")
        bothtrans200 = self.p.lookup_type("bothtrans200")

        edges = set(self.a.subG.out_edges_iter())
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

        self.a.set_reverse(False)
        self.a.set_exclude(["trans1"])
        self.a._build_subgraph()

        start = self.p.lookup_type("start")
        trans1 = self.p.lookup_type("trans1")
        trans2 = self.p.lookup_type("trans2")
        trans3 = self.p.lookup_type("trans3")
        trans4 = self.p.lookup_type("trans4")
        trans5 = self.p.lookup_type("trans5")
        dyntrans100 = self.p.lookup_type("dyntrans100")
        bothtrans200 = self.p.lookup_type("bothtrans200")

        edges = set(self.a.subG.out_edges_iter())
        self.assertSetEqual(set([(dyntrans100, bothtrans200),
                                 (start, dyntrans100),
                                 (trans2, trans3),
                                 (trans3, trans5)]), edges)

    def test_201_exclude_entryoint_with_2entrypoints(self):
        """DTA: exclude entrypoint type without transition deletion (other entrypoints)."""
        # Don't check node list since the disconnected nodes are not
        # removed after removing invalid domain transitions

        self.a.set_reverse(False)
        self.a.set_exclude(["trans3_exec1"])
        self.a._build_subgraph()

        start = self.p.lookup_type("start")
        trans1 = self.p.lookup_type("trans1")
        trans2 = self.p.lookup_type("trans2")
        trans3 = self.p.lookup_type("trans3")
        trans4 = self.p.lookup_type("trans4")
        trans5 = self.p.lookup_type("trans5")
        dyntrans100 = self.p.lookup_type("dyntrans100")
        bothtrans200 = self.p.lookup_type("bothtrans200")

        edges = set(self.a.subG.out_edges_iter())
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

        self.a.set_reverse(False)
        self.a.set_exclude(["bothtrans200_exec"])
        self.a._build_subgraph()

        start = self.p.lookup_type("start")
        trans1 = self.p.lookup_type("trans1")
        trans2 = self.p.lookup_type("trans2")
        trans3 = self.p.lookup_type("trans3")
        trans4 = self.p.lookup_type("trans4")
        trans5 = self.p.lookup_type("trans5")
        dyntrans100 = self.p.lookup_type("dyntrans100")
        bothtrans200 = self.p.lookup_type("bothtrans200")

        edges = set(self.a.subG.out_edges_iter())
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

        self.a.set_reverse(False)
        self.a.set_exclude(["trans2_exec"])
        self.a._build_subgraph()

        start = self.p.lookup_type("start")
        trans1 = self.p.lookup_type("trans1")
        trans2 = self.p.lookup_type("trans2")
        trans3 = self.p.lookup_type("trans3")
        trans4 = self.p.lookup_type("trans4")
        trans5 = self.p.lookup_type("trans5")
        dyntrans100 = self.p.lookup_type("dyntrans100")
        bothtrans200 = self.p.lookup_type("bothtrans200")

        edges = set(self.a.subG.out_edges_iter())
        self.assertSetEqual(set([(dyntrans100, bothtrans200),
                                 (start, dyntrans100),
                                 (start, trans1),
                                 (trans2, trans3),
                                 (trans3, trans5)]), edges)
