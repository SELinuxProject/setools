# Copyright 2014, Tresys Technology, LLC
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

from libapol import SELinuxPolicy
from libapol.dta import DomainTransitionAnalysis
from libapol.policyrep.rule import RuleNotConditional


class InfoFlowAnalysisTest(unittest.TestCase):

    def setUp(self):
        self.p = SELinuxPolicy("tests/dta.conf")
        self.a = DomainTransitionAnalysis(self.p)
        self.a._build_graph()

    def test_000_graph_structure(self):
        """DTA: verify graph structure."""
        # don't check node list since the disconnected nodes are not
        # removed after removing invalid domain transitions

        edges = sorted(list(self.a.G.out_edges_iter()))
        self.assertListEqual(edges, [("dyntrans100", "bothtrans200"),
                                     ("start", "dyntrans100"),
                                     ("start", "trans1"),
                                     ("trans1", "trans2"),
                                     ("trans2", "trans3"),
                                     ("trans3", "trans5")])

    def test_001_bothtrans(self):
        """DTA: type_transition, setexeccon(), and setcon() transitions."""

        s = "dyntrans100"
        t = "bothtrans200"
        e = "bothtrans200_exec"

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
        k = self.a.G.edge[s][t]["execute"].keys()
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
        k = self.a.G.edge[s][t]["entrypoint"].keys()
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
        k = self.a.G.edge[s][t]["type_transition"].keys()
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

        s = "start"
        t = "dyntrans100"

        # regular transition
        r = self.a.G.edge[s][t]["transition"]
        self.assertEqual(len(r), 0)

        # setexec perms
        r = self.a.G.edge[s][t]["setexec"]
        self.assertEqual(len(r), 0)

        # exec perms
        k = self.a.G.edge[s][t]["execute"].keys()
        self.assertEqual(len(k), 0)

        # entrypoint perms
        k = self.a.G.edge[s][t]["entrypoint"].keys()
        self.assertEqual(len(k), 0)

        # type_transition
        k = self.a.G.edge[s][t]["type_transition"].keys()
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

        s = "start"
        t = "trans1"
        e = "trans1_exec"

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
        k = self.a.G.edge[s][t]["execute"].keys()
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
        k = self.a.G.edge[s][t]["entrypoint"].keys()
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
        k = self.a.G.edge[s][t]["type_transition"].keys()
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

        s = "trans1"
        t = "trans2"
        e = "trans2_exec"

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
        k = self.a.G.edge[s][t]["execute"].keys()
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
        k = self.a.G.edge[s][t]["entrypoint"].keys()
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
        k = self.a.G.edge[s][t]["type_transition"].keys()
        self.assertEqual(len(k), 0)

        # dynamic transition
        r = self.a.G.edge[s][t]["dyntransition"]
        self.assertEqual(len(r), 0)

        # setcurrent
        r = self.a.G.edge[s][t]["setcurrent"]
        self.assertEqual(len(r), 0)

    def test_040_two_entrypoint(self):
        """DTA: 2 entrypoints, only one by type_transition."""

        s = "trans2"
        t = "trans3"
        e = ["trans3_exec1", "trans3_exec2"]

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
        k = self.a.G.edge[s][t]["execute"].keys()
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
        k = self.a.G.edge[s][t]["entrypoint"].keys()
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
        k = self.a.G.edge[s][t]["type_transition"].keys()
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

        s = "trans3"
        t = "trans5"
        e = "trans5_exec"

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
        k = self.a.G.edge[s][t]["execute"].keys()
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
        k = self.a.G.edge[s][t]["entrypoint"].keys()
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
        k = self.a.G.edge[s][t]["type_transition"].keys()
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
