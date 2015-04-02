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

from setools import SELinuxPolicy
from setools.rbacrulequery import RBACRuleQuery
from setools.policyrep.exception import RuleUseError, RuleNotConditional


class RBACRuleQueryTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.p = SELinuxPolicy("tests/rbacrulequery.conf")

    def test_000_unset(self):
        """RBAC rule query with no criteria."""
        # query with no parameters gets all RBAC rules.
        rules = sorted(self.p.rbacrules())

        q = RBACRuleQuery(self.p)
        q_rules = sorted(q.results())

        self.assertListEqual(rules, q_rules)

    def test_001_source_direct(self):
        """RBAC rule query with exact, direct, source match."""
        q = RBACRuleQuery(
            self.p, source="test1s", source_indirect=False, source_regex=False)

        r = sorted(q.results())
        self.assertEqual(len(r), 2)

        self.assertEqual(r[0].ruletype, "allow")
        self.assertEqual(r[0].source, "test1s")
        self.assertEqual(r[0].target, "test1t")
        self.assertRaises(RuleUseError, getattr, r[0], "tclass")
        self.assertRaises(RuleUseError, getattr, r[0], "default")
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

        self.assertEqual(r[1].ruletype, "role_transition")
        self.assertEqual(r[1].source, "test1s")
        self.assertEqual(r[1].target, "system")
        self.assertEqual(r[1].tclass, "infoflow")
        self.assertEqual(r[1].default, "test1t")
        self.assertRaises(RuleNotConditional, getattr, r[1], "conditional")

    def test_002_source_direct_regex(self):
        """RBAC rule query with regex, direct, source match."""
        q = RBACRuleQuery(
            self.p, source="test2s(1|2)", source_indirect=False, source_regex=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)

        self.assertEqual(r[0].ruletype, "allow")
        self.assertEqual(r[0].source, "test2s1")
        self.assertEqual(r[0].target, "test2t")
        self.assertRaises(RuleUseError, getattr, r[0], "tclass")
        self.assertRaises(RuleUseError, getattr, r[0], "default")
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

    def test_010_target_direct(self):
        """RBAC rule query with exact, direct, target match."""
        q = RBACRuleQuery(
            self.p, target="test10t", target_indirect=False, target_regex=False)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)

        self.assertEqual(r[0].ruletype, "allow")
        self.assertEqual(r[0].source, "test10s")
        self.assertEqual(r[0].target, "test10t")
        self.assertRaises(RuleUseError, getattr, r[0], "tclass")
        self.assertRaises(RuleUseError, getattr, r[0], "default")
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

    def test_011_target_direct_regex(self):
        """RBAC rule query with regex, direct, target match."""
        q = RBACRuleQuery(
            self.p, target="test11t(1|3)", target_indirect=False, target_regex=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)

        self.assertEqual(r[0].ruletype, "allow")
        self.assertEqual(r[0].source, "test11s")
        self.assertEqual(r[0].target, "test11t1")
        self.assertRaises(RuleUseError, getattr, r[0], "tclass")
        self.assertRaises(RuleUseError, getattr, r[0], "default")
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

    def test_020_class(self):
        """RBAC rule query with exact object class match."""
        q = RBACRuleQuery(self.p, tclass="infoflow2", tclass_regex=False)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)

        self.assertEqual(r[0].ruletype, "role_transition")
        self.assertEqual(r[0].source, "test20")
        self.assertEqual(r[0].target, "system")
        self.assertEqual(r[0].tclass, "infoflow2")
        self.assertEqual(r[0].default, "test20d2")
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

    def test_021_class_list(self):
        """RBAC rule query with object class list match."""
        q = RBACRuleQuery(
            self.p, tclass=["infoflow3", "infoflow4"], tclass_regex=False)

        r = sorted(q.results())
        self.assertEqual(len(r), 2)

        self.assertEqual(r[0].ruletype, "role_transition")
        self.assertEqual(r[0].source, "test21")
        self.assertEqual(r[0].target, "system")
        self.assertEqual(r[0].tclass, "infoflow3")
        self.assertEqual(r[0].default, "test21d3")
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

        self.assertEqual(r[1].ruletype, "role_transition")
        self.assertEqual(r[1].source, "test21")
        self.assertEqual(r[1].target, "system")
        self.assertEqual(r[1].tclass, "infoflow4")
        self.assertEqual(r[1].default, "test21d2")
        self.assertRaises(RuleNotConditional, getattr, r[1], "conditional")

    def test_022_class_regex(self):
        """RBAC rule query with object class regex match."""
        q = RBACRuleQuery(self.p, tclass="infoflow(5|6)", tclass_regex=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 2)

        self.assertEqual(r[0].ruletype, "role_transition")
        self.assertEqual(r[0].source, "test22")
        self.assertEqual(r[0].target, "system")
        self.assertEqual(r[0].tclass, "infoflow5")
        self.assertEqual(r[0].default, "test22d2")
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

        self.assertEqual(r[1].ruletype, "role_transition")
        self.assertEqual(r[1].source, "test22")
        self.assertEqual(r[1].target, "system")
        self.assertEqual(r[1].tclass, "infoflow6")
        self.assertEqual(r[0].default, "test22d2")
        self.assertRaises(RuleNotConditional, getattr, r[1], "conditional")

    def test_030_default(self):
        """RBAC rule query with exact default match."""
        q = RBACRuleQuery(
            self.p, default="test30d", default_regex=False)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)

        self.assertEqual(r[0].ruletype, "role_transition")
        self.assertEqual(r[0].source, "test30s")
        self.assertEqual(r[0].target, "system")
        self.assertEqual(r[0].tclass, "infoflow")
        self.assertEqual(r[0].default, "test30d")
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

    def test_031_default_regex(self):
        """RBAC rule query with regex default match."""
        q = RBACRuleQuery(
            self.p, default="test31d(2|3)", default_regex=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 2)

        self.assertEqual(r[0].ruletype, "role_transition")
        self.assertEqual(r[0].source, "test31s")
        self.assertEqual(r[0].target, "system")
        self.assertEqual(r[0].tclass, "infoflow7")
        self.assertEqual(r[0].default, "test31d3")
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

        self.assertEqual(r[1].ruletype, "role_transition")
        self.assertEqual(r[1].source, "test31s")
        self.assertEqual(r[1].target, "system")
        self.assertEqual(r[1].tclass, "process")
        self.assertEqual(r[1].default, "test31d2")
        self.assertRaises(RuleNotConditional, getattr, r[1], "conditional")

    def test_040_ruletype(self):
        """RBAC rule query with rule type."""
        q = RBACRuleQuery(self.p, ruletype=["allow"])

        for num, r in enumerate(sorted(q.results()), start=1):
            self.assertEqual(r.ruletype, "allow")

        # this will have to be updated as number of
        # role allows change in the test policy
        self.assertEqual(num, 8)
