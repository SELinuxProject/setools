# Copyright 2014, Tresys Technology, LLC
#
# SPDX-License-Identifier: GPL-2.0-only
#
import pytest
import setools
from setools import MLSRuleQuery
from setools import MLSRuletype as RT

from . import util

# Note: the test policy has been written assuming range_transition
# statements could have attributes.  However, range_transition
# statements are always expanded, so the below unit tests
# have been adjusted to this fact (hence a "FAIL" in one of the
# expected type names)


@pytest.mark.obj_args("tests/library/mlsrulequery.conf")
class TestMLSRuleQuery:

    def test_unset(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """MLS rule query with no criteria."""
        # query with no parameters gets all MLS rules.
        rules = sorted(compiled_policy.mlsrules())

        q = MLSRuleQuery(compiled_policy)
        q_rules = sorted(q.results())

        assert rules == q_rules

    def test_source_direct(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """MLS rule query with exact, direct, source match."""
        q = MLSRuleQuery(
            compiled_policy, source="test1s", source_regex=False)

        r = sorted(q.results())
        assert len(r) == 1
        util.validate_rule(r[0], RT.range_transition, "test1s", "test1t", tclass="infoflow",
                           default="s0")

    def test_source_direct_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """MLS rule query with regex, direct, source match."""
        q = MLSRuleQuery(
            compiled_policy, source="test3(s|aS)", source_regex=True)

        r = sorted(q.results())
        assert len(r) == 2
        util.validate_rule(r[0], RT.range_transition, "test3s", "test3t", tclass="infoflow",
                           default="s1")
        util.validate_rule(r[1], RT.range_transition, "test3s", "test3t", tclass="infoflow2",
                           default="s2")

    def test_issue111(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """MLS rule query with attribute source criteria, indirect match."""
        # https://github.com/TresysTechnology/setools/issues/111
        q = MLSRuleQuery(compiled_policy, source="test5b", source_indirect=True)

        r = sorted(q.results())
        assert len(r) == 2
        util.validate_rule(r[0], RT.range_transition, "test5t1", "test5target", tclass="infoflow",
                           default="s1")
        util.validate_rule(r[1], RT.range_transition, "test5t2", "test5target", tclass="infoflow7",
                           default="s2")

    def test_target_direct(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """MLS rule query with exact, direct, target match."""
        q = MLSRuleQuery(
            compiled_policy, target="test10t", target_regex=False)

        r = sorted(q.results())
        assert len(r) == 2
        util.validate_rule(r[0], RT.range_transition, "test10s", "test10t", tclass="infoflow",
                           default="s0")
        util.validate_rule(r[1], RT.range_transition, "test10s", "test10t", tclass="infoflow2",
                           default="s1")

    def test_target_direct_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """MLS rule query with regex, direct, target match."""
        q = MLSRuleQuery(
            compiled_policy, target="test12a.*", target_regex=True)

        r = sorted(q.results())
        assert len(r) == 1
        util.validate_rule(r[0], RT.range_transition, "test12s", "test12aFAIL", tclass="infoflow",
                           default="s2")

    def test_issue111_2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """MLS rule query with attribute target criteria, indirect match."""
        # https://github.com/TresysTechnology/setools/issues/111
        q = MLSRuleQuery(compiled_policy, target="test14b", target_indirect=True)

        r = sorted(q.results())
        assert len(r) == 2
        util.validate_rule(r[0], RT.range_transition, "test14source", "test14t1",
                           tclass="infoflow", default="s1")
        util.validate_rule(r[1], RT.range_transition, "test14source", "test14t2",
                           tclass="infoflow7", default="s2")

    def test_class_list(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """MLS rule query with object class list match."""
        q = MLSRuleQuery(
            compiled_policy, tclass=["infoflow3", "infoflow4"], tclass_regex=False)

        r = sorted(q.results())
        assert len(r) == 2
        util.validate_rule(r[0], RT.range_transition, "test21", "test21", tclass="infoflow3",
                           default="s2")
        util.validate_rule(r[1], RT.range_transition, "test21", "test21", tclass="infoflow4",
                           default="s1")

    def test_class_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """MLS rule query with object class regex match."""
        q = MLSRuleQuery(compiled_policy, tclass="infoflow(5|6)", tclass_regex=True)

        r = sorted(q.results())
        assert len(r) == 2
        util.validate_rule(r[0], RT.range_transition, "test22", "test22", tclass="infoflow5",
                           default="s1")
        util.validate_rule(r[1], RT.range_transition, "test22", "test22", tclass="infoflow6",
                           default="s2")

    def test_range_exact(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """MLS rule query with context range exact match"""
        q = MLSRuleQuery(compiled_policy, default="s40:c1 - s40:c0.c4")

        r = sorted(q.results())
        assert len(r) == 1
        util.validate_rule(r[0], RT.range_transition, "test40", "test40", tclass="infoflow",
                           default="s40:c1 - s40:c0.c4")

    def test_range_overlap1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """MLS rule query with context range overlap match (equal)"""
        q = MLSRuleQuery(compiled_policy, default="s41:c1 - s41:c0.c4", default_overlap=True)

        r = sorted(q.results())
        assert len(r) == 1
        util.validate_rule(r[0], RT.range_transition, "test41", "test41", tclass="infoflow",
                           default="s41:c1 - s41:c1.c3")

    def test_range_overlap2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """MLS rule query with context range overlap match (subset)"""
        q = MLSRuleQuery(compiled_policy, default="s41:c1,c2 - s41:c0.c3", default_overlap=True)

        r = sorted(q.results())
        assert len(r) == 1
        util.validate_rule(r[0], RT.range_transition, "test41", "test41", tclass="infoflow",
                           default="s41:c1 - s41:c1.c3")

    def test_range_overlap3(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """MLS rule query with context range overlap match (superset)"""
        q = MLSRuleQuery(compiled_policy, default="s41 - s41:c0.c4", default_overlap=True)

        r = sorted(q.results())
        assert len(r) == 1
        util.validate_rule(r[0], RT.range_transition, "test41", "test41", tclass="infoflow",
                           default="s41:c1 - s41:c1.c3")

    def test_range_overlap4(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """MLS rule query with context range overlap match (overlap low level)"""
        q = MLSRuleQuery(compiled_policy, default="s41 - s41:c1,c2", default_overlap=True)

        r = sorted(q.results())
        assert len(r) == 1
        util.validate_rule(r[0], RT.range_transition, "test41", "test41", tclass="infoflow",
                           default="s41:c1 - s41:c1.c3")

    def test_range_overlap5(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """MLS rule query with context range overlap match (overlap high level)"""
        q = MLSRuleQuery(compiled_policy, default="s41:c1,c2 - s41:c0.c4", default_overlap=True)

        r = sorted(q.results())
        assert len(r) == 1
        util.validate_rule(r[0], RT.range_transition, "test41", "test41", tclass="infoflow",
                           default="s41:c1 - s41:c1.c3")

    def test_range_subset1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """MLS rule query with context range subset match"""
        q = MLSRuleQuery(compiled_policy, default="s42:c1,c2 - s42:c0.c3", default_overlap=True)

        r = sorted(q.results())
        assert len(r) == 1
        util.validate_rule(r[0], RT.range_transition, "test42", "test42", tclass="infoflow",
                           default="s42:c1 - s42:c1.c3")

    def test_range_subset2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """MLS rule query with context range subset match (equal)"""
        q = MLSRuleQuery(compiled_policy, default="s42:c1 - s42:c1.c3", default_overlap=True)

        r = sorted(q.results())
        assert len(r) == 1
        util.validate_rule(r[0], RT.range_transition, "test42", "test42", tclass="infoflow",
                           default="s42:c1 - s42:c1.c3")

    def test_range_superset1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """MLS rule query with context range superset match"""
        q = MLSRuleQuery(compiled_policy, default="s43 - s43:c0.c4", default_superset=True)

        r = sorted(q.results())
        assert len(r) == 1
        util.validate_rule(r[0], RT.range_transition, "test43", "test43", tclass="infoflow",
                           default="s43:c1 - s43:c1.c3")

    def test_range_superset2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """MLS rule query with context range superset match (equal)"""
        q = MLSRuleQuery(compiled_policy, default="s43:c1 - s43:c1.c3", default_superset=True)

        r = sorted(q.results())
        assert len(r) == 1
        util.validate_rule(r[0], RT.range_transition, "test43", "test43", tclass="infoflow",
                           default="s43:c1 - s43:c1.c3")

    def test_range_proper_subset1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """MLS rule query with context range proper subset match"""
        q = MLSRuleQuery(compiled_policy, default="s44:c1,c2", default_subset=True,
                         default_proper=True)

        r = sorted(q.results())
        assert len(r) == 1
        util.validate_rule(r[0], RT.range_transition, "test44", "test44", tclass="infoflow",
                           default="s44:c1 - s44:c1.c3")

    def test_range_proper_subset2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """MLS rule query with context range proper subset match (equal)"""
        q = MLSRuleQuery(compiled_policy, default="s44:c1 - s44:c1.c3", default_subset=True,
                         default_proper=True)

        r = sorted(q.results())
        assert len(r) == 0

    def test_range_proper_subset3(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """MLS rule query with context range proper subset match (equal low only)"""
        q = MLSRuleQuery(compiled_policy, default="s44:c1 - s44:c1.c2", default_subset=True,
                         default_proper=True)

        r = sorted(q.results())
        assert len(r) == 1
        util.validate_rule(r[0], RT.range_transition, "test44", "test44", tclass="infoflow",
                           default="s44:c1 - s44:c1.c3")

    def test_range_proper_subset4(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """MLS rule query with context range proper subset match (equal high only)"""
        q = MLSRuleQuery(compiled_policy, default="s44:c1,c2 - s44:c1.c3", default_subset=True,
                         default_proper=True)

        r = sorted(q.results())
        assert len(r) == 1
        util.validate_rule(r[0], RT.range_transition, "test44", "test44", tclass="infoflow",
                           default="s44:c1 - s44:c1.c3")

    def test_range_proper_superset1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """MLS rule query with context range proper superset match"""
        q = MLSRuleQuery(compiled_policy, default="s45 - s45:c0.c4", default_superset=True,
                         default_proper=True)

        r = sorted(q.results())
        assert len(r) == 1
        util.validate_rule(r[0], RT.range_transition, "test45", "test45", tclass="infoflow",
                           default="s45:c1 - s45:c1.c3")

    def test_range_proper_superset2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """MLS rule query with context range proper superset match (equal)"""
        q = MLSRuleQuery(compiled_policy, default="s45:c1 - s45:c1.c3", default_superset=True,
                         default_proper=True)

        r = sorted(q.results())
        assert len(r) == 0

    def test_range_proper_superset3(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """MLS rule query with context range proper superset match (equal low)"""
        q = MLSRuleQuery(compiled_policy, default="s45:c1 - s45:c1.c4", default_superset=True,
                         default_proper=True)

        r = sorted(q.results())
        assert len(r) == 1
        util.validate_rule(r[0], RT.range_transition, "test45", "test45", tclass="infoflow",
                           default="s45:c1 - s45:c1.c3")

    def test_range_proper_superset4(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """MLS rule query with context range proper superset match (equal high)"""
        q = MLSRuleQuery(compiled_policy, default="s45 - s45:c1.c3", default_superset=True,
                         default_proper=True)

        r = sorted(q.results())
        assert len(r) == 1
        util.validate_rule(r[0], RT.range_transition, "test45", "test45", tclass="infoflow",
                           default="s45:c1 - s45:c1.c3")

    def test_invalid_ruletype(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """MLS rule query with invalid rule type."""
        with pytest.raises(KeyError):
            q = MLSRuleQuery(compiled_policy, ruletype=["type_transition"])
