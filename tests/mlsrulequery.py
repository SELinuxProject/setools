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
from setools.mlsrulequery import MLSRuleQuery
from setools.policyrep.rule import RuleNotConditional

# Note: the test policy has been written assuming range_transition
# statements could have attributes.  However, range_transition
# statements are always expanded, so the below unit tests
# have been adjusted to this fact (hence a "FAIL" in one of the
# expected type names)


class MLSRuleQueryTest(unittest.TestCase):

    def setUp(self):
        self.p = SELinuxPolicy("tests/mlsrulequery.conf")

    def test_000_unset(self):
        """MLS rule query with no criteria."""
        # query with no parameters gets all MLS rules.
        rules = sorted(self.p.mlsrules())

        q = MLSRuleQuery(self.p)
        q_rules = sorted(q.results())

        self.assertListEqual(rules, q_rules)

    def test_001_source_direct(self):
        """MLS rule query with exact, direct, source match."""
        q = MLSRuleQuery(
            self.p, source="test1s", source_regex=False)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)

        self.assertEqual(r[0].ruletype, "range_transition")
        self.assertEqual(r[0].source, "test1s")
        self.assertEqual(r[0].target, "test1t")
        self.assertEqual(r[0].tclass, "infoflow")
        self.assertEqual(r[0].default, "s0")
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

    def test_003_source_direct_regex(self):
        """MLS rule query with regex, direct, source match."""
        q = MLSRuleQuery(
            self.p, source="test3(s|aS)", source_regex=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 2)

        self.assertEqual(r[0].ruletype, "range_transition")
        self.assertEqual(r[0].source, "test3s")
        self.assertEqual(r[0].target, "test3t")
        self.assertEqual(r[0].tclass, "infoflow")
        self.assertEqual(r[0].default, "s1")
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

        self.assertEqual(r[1].ruletype, "range_transition")
        self.assertEqual(r[1].source, "test3s")
        self.assertEqual(r[1].target, "test3t")
        self.assertEqual(r[1].tclass, "infoflow2")
        self.assertEqual(r[1].default, "s2")
        self.assertRaises(RuleNotConditional, getattr, r[1], "conditional")

    def test_010_target_direct(self):
        """MLS rule query with exact, direct, target match."""
        q = MLSRuleQuery(
            self.p, target="test10t", target_regex=False)

        r = sorted(q.results())
        self.assertEqual(len(r), 2)

        self.assertEqual(r[0].ruletype, "range_transition")
        self.assertEqual(r[0].source, "test10s")
        self.assertEqual(r[0].target, "test10t")
        self.assertEqual(r[0].tclass, "infoflow")
        self.assertEqual(r[0].default, "s0")
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

        self.assertEqual(r[1].ruletype, "range_transition")
        self.assertEqual(r[1].source, "test10s")
        self.assertEqual(r[1].target, "test10t")
        self.assertEqual(r[1].tclass, "infoflow2")
        self.assertEqual(r[1].default, "s1")
        self.assertRaises(RuleNotConditional, getattr, r[1], "conditional")

    def test_012_target_direct_regex(self):
        """MLS rule query with regex, direct, target match."""
        q = MLSRuleQuery(
            self.p, target="test12a.*", target_regex=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)

        self.assertEqual(r[0].ruletype, "range_transition")
        self.assertEqual(r[0].source, "test12s")
        self.assertEqual(r[0].target, "test12aFAIL")
        self.assertEqual(r[0].tclass, "infoflow")
        self.assertEqual(r[0].default, "s2")
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

    def test_020_class(self):
        """MLS rule query with exact object class match."""
        q = MLSRuleQuery(self.p, tclass="infoflow7", tclass_regex=False)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)

        self.assertEqual(r[0].ruletype, "range_transition")
        self.assertEqual(r[0].source, "test20")
        self.assertEqual(r[0].target, "test20")
        self.assertEqual(r[0].tclass, "infoflow7")
        self.assertEqual(r[0].default, "s1")
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

    def test_021_class_list(self):
        """MLS rule query with object class list match."""
        q = MLSRuleQuery(
            self.p, tclass=["infoflow3", "infoflow4"], tclass_regex=False)

        r = sorted(q.results())
        self.assertEqual(len(r), 2)

        # verify first rule
        self.assertEqual(r[0].ruletype, "range_transition")
        self.assertEqual(r[0].source, "test21")
        self.assertEqual(r[0].target, "test21")
        self.assertEqual(r[0].tclass, "infoflow3")
        self.assertEqual(r[0].default, "s2")
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

        # verify second rule
        self.assertEqual(r[1].ruletype, "range_transition")
        self.assertEqual(r[1].source, "test21")
        self.assertEqual(r[1].target, "test21")
        self.assertEqual(r[1].tclass, "infoflow4")
        self.assertEqual(r[1].default, "s1")
        self.assertRaises(RuleNotConditional, getattr, r[1], "conditional")

    def test_022_class_regex(self):
        """MLS rule query with object class regex match."""
        q = MLSRuleQuery(self.p, tclass="infoflow(5|6)", tclass_regex=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 2)

        # verify first rule
        self.assertEqual(r[0].ruletype, "range_transition")
        self.assertEqual(r[0].source, "test22")
        self.assertEqual(r[0].target, "test22")
        self.assertEqual(r[0].tclass, "infoflow5")
        self.assertEqual(r[0].default, "s1")
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

        # verify second rule
        self.assertEqual(r[1].ruletype, "range_transition")
        self.assertEqual(r[1].source, "test22")
        self.assertEqual(r[1].target, "test22")
        self.assertEqual(r[1].tclass, "infoflow6")
        self.assertEqual(r[1].default, "s2")
        self.assertRaises(RuleNotConditional, getattr, r[1], "conditional")

    def test_040_range_exact(self):
        """MLS rule query query with context range exact match"""
        q = MLSRuleQuery(self.p, default="s40:c1 - s40:c0.c4")

        r = sorted(q.results())
        self.assertEqual(len(r), 1)

        self.assertEqual(r[0].ruletype, "range_transition")
        self.assertEqual(r[0].source, "test40")
        self.assertEqual(r[0].target, "test40")
        self.assertEqual(r[0].tclass, "infoflow")
        self.assertEqual(r[0].default, "s40:c1 - s40:c0.c4")
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

    def test_041_range_overlap1(self):
        """MLS rule query query with context range overlap match (equal)"""
        q = MLSRuleQuery(self.p, default="s41:c1 - s41:c0.c4", default_overlap=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)

        self.assertEqual(r[0].ruletype, "range_transition")
        self.assertEqual(r[0].source, "test41")
        self.assertEqual(r[0].target, "test41")
        self.assertEqual(r[0].tclass, "infoflow")
        self.assertEqual(r[0].default, "s41:c1 - s41:c1.c3")
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

    def test_041_range_overlap2(self):
        """MLS rule query query with context range overlap match (subset)"""
        q = MLSRuleQuery(self.p, default="s41:c1,c2 - s41:c0.c3", default_overlap=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)

        self.assertEqual(r[0].ruletype, "range_transition")
        self.assertEqual(r[0].source, "test41")
        self.assertEqual(r[0].target, "test41")
        self.assertEqual(r[0].tclass, "infoflow")
        self.assertEqual(r[0].default, "s41:c1 - s41:c1.c3")
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

    def test_041_range_overlap3(self):
        """MLS rule query query with context range overlap match (superset)"""
        q = MLSRuleQuery(self.p, default="s41 - s41:c0.c4", default_overlap=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)

        self.assertEqual(r[0].ruletype, "range_transition")
        self.assertEqual(r[0].source, "test41")
        self.assertEqual(r[0].target, "test41")
        self.assertEqual(r[0].tclass, "infoflow")
        self.assertEqual(r[0].default, "s41:c1 - s41:c1.c3")
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

    def test_041_range_overlap4(self):
        """MLS rule query query with context range overlap match (overlap low level)"""
        q = MLSRuleQuery(self.p, default="s41 - s41:c1,c2", default_overlap=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)

        self.assertEqual(r[0].ruletype, "range_transition")
        self.assertEqual(r[0].source, "test41")
        self.assertEqual(r[0].target, "test41")
        self.assertEqual(r[0].tclass, "infoflow")
        self.assertEqual(r[0].default, "s41:c1 - s41:c1.c3")
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

    def test_041_range_overlap5(self):
        """MLS rule query query with context range overlap match (overlap high level)"""
        q = MLSRuleQuery(self.p, default="s41:c1,c2 - s41:c0.c4", default_overlap=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)

        self.assertEqual(r[0].ruletype, "range_transition")
        self.assertEqual(r[0].source, "test41")
        self.assertEqual(r[0].target, "test41")
        self.assertEqual(r[0].tclass, "infoflow")
        self.assertEqual(r[0].default, "s41:c1 - s41:c1.c3")
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

    def test_042_range_subset1(self):
        """MLS rule query query with context range subset match"""
        q = MLSRuleQuery(self.p, default="s42:c1,c2 - s42:c0.c3", default_overlap=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)

        self.assertEqual(r[0].ruletype, "range_transition")
        self.assertEqual(r[0].source, "test42")
        self.assertEqual(r[0].target, "test42")
        self.assertEqual(r[0].tclass, "infoflow")
        self.assertEqual(r[0].default, "s42:c1 - s42:c1.c3")
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

    def test_042_range_subset2(self):
        """MLS rule query query with context range subset match (equal)"""
        q = MLSRuleQuery(self.p, default="s42:c1 - s42:c1.c3", default_overlap=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)

        self.assertEqual(r[0].ruletype, "range_transition")
        self.assertEqual(r[0].source, "test42")
        self.assertEqual(r[0].target, "test42")
        self.assertEqual(r[0].tclass, "infoflow")
        self.assertEqual(r[0].default, "s42:c1 - s42:c1.c3")
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

    def test_043_range_superset1(self):
        """MLS rule query query with context range superset match"""
        q = MLSRuleQuery(self.p, default="s43 - s43:c0.c4", default_superset=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)

        self.assertEqual(r[0].ruletype, "range_transition")
        self.assertEqual(r[0].source, "test43")
        self.assertEqual(r[0].target, "test43")
        self.assertEqual(r[0].tclass, "infoflow")
        self.assertEqual(r[0].default, "s43:c1 - s43:c1.c3")
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

    def test_043_range_superset2(self):
        """MLS rule query query with context range superset match (equal)"""
        q = MLSRuleQuery(self.p, default="s43:c1 - s43:c1.c3", default_superset=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)

        self.assertEqual(r[0].ruletype, "range_transition")
        self.assertEqual(r[0].source, "test43")
        self.assertEqual(r[0].target, "test43")
        self.assertEqual(r[0].tclass, "infoflow")
        self.assertEqual(r[0].default, "s43:c1 - s43:c1.c3")
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

    def test_044_range_proper_subset1(self):
        """MLS rule query query with context range proper subset match"""
        q = MLSRuleQuery(self.p, default="s44:c1,c2", default_subset=True, default_proper=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)

        self.assertEqual(r[0].ruletype, "range_transition")
        self.assertEqual(r[0].source, "test44")
        self.assertEqual(r[0].target, "test44")
        self.assertEqual(r[0].tclass, "infoflow")
        self.assertEqual(r[0].default, "s44:c1 - s44:c1.c3")
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

    def test_044_range_proper_subset2(self):
        """MLS rule query query with context range proper subset match (equal)"""
        q = MLSRuleQuery(self.p,
                         default="s44:c1 - s44:c1.c3", default_subset=True, default_proper=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 0)

    def test_044_range_proper_subset3(self):
        """MLS rule query query with context range proper subset match (equal low only)"""
        q = MLSRuleQuery(self.p,
                         default="s44:c1 - s44:c1.c2", default_subset=True, default_proper=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)

        self.assertEqual(r[0].ruletype, "range_transition")
        self.assertEqual(r[0].source, "test44")
        self.assertEqual(r[0].target, "test44")
        self.assertEqual(r[0].tclass, "infoflow")
        self.assertEqual(r[0].default, "s44:c1 - s44:c1.c3")
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

    def test_044_range_proper_subset4(self):
        """MLS rule query query with context range proper subset match (equal high only)"""
        q = MLSRuleQuery(self.p,
                         default="s44:c1,c2 - s44:c1.c3", default_subset=True, default_proper=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)

        self.assertEqual(r[0].ruletype, "range_transition")
        self.assertEqual(r[0].source, "test44")
        self.assertEqual(r[0].target, "test44")
        self.assertEqual(r[0].tclass, "infoflow")
        self.assertEqual(r[0].default, "s44:c1 - s44:c1.c3")
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

    def test_045_range_proper_superset1(self):
        """MLS rule query query with context range proper superset match"""
        q = MLSRuleQuery(self.p,
                         default="s45 - s45:c0.c4", default_superset=True, default_proper=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)

        self.assertEqual(r[0].ruletype, "range_transition")
        self.assertEqual(r[0].source, "test45")
        self.assertEqual(r[0].target, "test45")
        self.assertEqual(r[0].tclass, "infoflow")
        self.assertEqual(r[0].default, "s45:c1 - s45:c1.c3")
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

    def test_045_range_proper_superset2(self):
        """MLS rule query query with context range proper superset match (equal)"""
        q = MLSRuleQuery(self.p,
                         default="s45:c1 - s45:c1.c3", default_superset=True, default_proper=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 0)

    def test_045_range_proper_superset3(self):
        """MLS rule query query with context range proper superset match (equal low)"""
        q = MLSRuleQuery(self.p,
                         default="s45:c1 - s45:c1.c4", default_superset=True, default_proper=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)

        self.assertEqual(r[0].ruletype, "range_transition")
        self.assertEqual(r[0].source, "test45")
        self.assertEqual(r[0].target, "test45")
        self.assertEqual(r[0].tclass, "infoflow")
        self.assertEqual(r[0].default, "s45:c1 - s45:c1.c3")
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")

    def test_045_range_proper_superset4(self):
        """MLS rule query query with context range proper superset match (equal high)"""
        q = MLSRuleQuery(self.p,
                         default="s45 - s45:c1.c3", default_superset=True, default_proper=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)

        self.assertEqual(r[0].ruletype, "range_transition")
        self.assertEqual(r[0].source, "test45")
        self.assertEqual(r[0].target, "test45")
        self.assertEqual(r[0].tclass, "infoflow")
        self.assertEqual(r[0].default, "s45:c1 - s45:c1.c3")
        self.assertRaises(RuleNotConditional, getattr, r[0], "conditional")
