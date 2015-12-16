# Derived from tests/XpermRuleQuery.py
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

from setools import SELinuxPolicy, XpermRuleQuery

from . import mixins


class XpermRuleQueryTest(mixins.ValidateXpermRule, unittest.TestCase):

    """xperm ioctl rule query unit tests."""

    @classmethod
    def setUpClass(cls):
        cls.p = SELinuxPolicy("tests/xpermrulequery.conf")

    def test_000_unset(self):
        """xperm rule query with no criteria."""
        # query with no parameters gets all Xperm rules.
        rules = sorted(self.p.xpermrules())

        q = XpermRuleQuery(self.p)
        q_rules = sorted(q.results())

        self.assertListEqual(rules, q_rules)

    def test_001_source_direct(self):
        """Xperm rule query with exact, direct, source match."""
        q = XpermRuleQuery(
            self.p, source="test1a", source_indirect=False, source_regex=False)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)
        self.validate_xperm_rule(r[0], "allowxperm", "test1a", "test1t", "infoflow")

    def test_002_source_indirect(self):
        """Xperm rule query with exact, indirect, source match."""
        q = XpermRuleQuery(
            self.p, source="test2s", source_indirect=True, source_regex=False)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)
        self.validate_xperm_rule(r[0], "allowxperm", "test2a", "test2t", "infoflow")

    def test_003_source_direct_regex(self):
        """Xperm rule query with regex, direct, source match."""
        q = XpermRuleQuery(
            self.p, source="test3a.*", source_indirect=False, source_regex=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)
        self.validate_xperm_rule(r[0], "allowxperm", "test3aS", "test3t", "infoflow")

    def test_004_source_indirect_regex(self):
        """Xperm rule query with regex, indirect, source match."""
        q = XpermRuleQuery(
            self.p, source="test4(s|t)", source_indirect=True, source_regex=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 2)
        self.validate_xperm_rule(r[0], "allowxperm", "test4a1", "test4a1", "infoflow")
        self.validate_xperm_rule(r[1], "allowxperm", "test4a2", "test4a2", "infoflow")

    def test_005_target_direct(self):
        """Xperm rule query with exact, direct, target match."""
        q = XpermRuleQuery(
            self.p, target="test5a", target_indirect=False, target_regex=False)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)
        self.validate_xperm_rule(r[0], "allowxperm", "test5s", "test5a", "infoflow")

    def test_006_target_indirect(self):
        """Xperm rule query with exact, indirect, target match."""
        q = XpermRuleQuery(
            self.p, target="test6t", target_indirect=True, target_regex=False)

        r = sorted(q.results())
        self.assertEqual(len(r), 2)
        self.validate_xperm_rule(r[0], "allowxperm", "test6s", "test6a", "infoflow")
        self.validate_xperm_rule(r[1], "allowxperm", "test6s", "test6t", "infoflow")

    def test_007_target_direct_regex(self):
        """Xperm rule query with regex, direct, target match."""
        q = XpermRuleQuery(
            self.p, target="test7a.*", target_indirect=False, target_regex=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)
        self.validate_xperm_rule(r[0], "allowxperm", "test7s", "test7aPASS", "infoflow")

    def test_008_target_indirect_regex(self):
        """Xperm rule query with regex, indirect, target match."""
        q = XpermRuleQuery(
            self.p, target="test8(s|t)", target_indirect=True, target_regex=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 2)
        self.validate_xperm_rule(r[0], "allowxperm", "test8a1", "test8a1", "infoflow")
        self.validate_xperm_rule(r[1], "allowxperm", "test8a2", "test8a2", "infoflow")

    @unittest.skip("Setting tclass to a string is no longer supported.")
    def test_009_class(self):
        """Xperm rule query with exact object class match."""
        q = XpermRuleQuery(self.p, tclass="infoflow2", tclass_regex=False)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)
        self.validate_xperm_rule(r[0], "allowxperm", "test9", "test9", "infoflow2")

    def test_010_class_list(self):
        """Xperm rule query with object class list match."""
        q = XpermRuleQuery(
            self.p, tclass=["infoflow3", "infoflow4"], tclass_regex=False)

        r = sorted(q.results())
        self.assertEqual(len(r), 2)
        self.validate_xperm_rule(r[0], "allowxperm", "test10", "test10", "infoflow3")
        self.validate_xperm_rule(r[1], "allowxperm", "test10", "test10", "infoflow4")

    def test_011_class_regex(self):
        """Xperm rule query with object class regex match."""
        q = XpermRuleQuery(self.p, tclass="infoflow(5|6)", tclass_regex=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 2)
        self.validate_xperm_rule(r[0], "allowxperm", "test11", "test11", "infoflow5")
        self.validate_xperm_rule(r[1], "allowxperm", "test11", "test11", "infoflow6")


    def test_014_ruletype(self):
        """Xperm rule query with rule type match."""
        q = XpermRuleQuery(self.p, ruletype=["auditallowxperm", "dontauditxperm"])

        r = sorted(q.results())
        self.assertEqual(len(r), 2)
        self.validate_xperm_rule(r[0], "auditallowxperm", "test14", "test14", "infoflow7")
        self.validate_xperm_rule(r[1], "dontauditxperm", "test14", "test14", "infoflow7")

