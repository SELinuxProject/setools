"""RBAC rule query unit tests."""
# Copyright 2014, Tresys Technology, LLC
#
# SPDX-License-Identifier: GPL-2.0-only
#
# pylint: disable=invalid-name,too-many-public-methods
import pytest
import setools
from setools import RBACRuleQuery
from setools import RBACRuletype as RRT
from setools.exception import RuleUseError, RuleNotConditional

from . import mixins


@pytest.mark.obj_args("tests/library/rbacrulequery.conf")
class TestRBACRuleQuery(mixins.ValidateRule):

    """RBAC rule query unit tests."""

    def validate_allow(self, rule, source, target) -> None:
        """Validate a role allow rule."""
        assert RRT.allow == rule.ruletype
        assert source == rule.source
        assert target == rule.target
        with pytest.raises(RuleUseError):
            rule.tclass
        with pytest.raises(RuleUseError):
            rule.default
        with pytest.raises(RuleNotConditional):
            rule.conditional

    def test_unset(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """RBAC rule query with no criteria."""
        # query with no parameters gets all RBAC rules.
        rules = sorted(compiled_policy.rbacrules())

        q = RBACRuleQuery(compiled_policy)
        q_rules = sorted(q.results())

        assert rules == q_rules

    def test_source_direct(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """RBAC rule query with exact, direct, source match."""
        q = RBACRuleQuery(
            compiled_policy, source="test1s", source_indirect=False, source_regex=False)

        r = sorted(q.results())
        assert len(r) == 2

        self.validate_allow(r[0], "test1s", "test1t")
        self.validate_rule(r[1], RRT.role_transition, "test1s", "system", "infoflow", "test1t")

    def test_source_direct_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """RBAC rule query with regex, direct, source match."""
        q = RBACRuleQuery(
            compiled_policy, source="test2s(1|2)", source_indirect=False, source_regex=True)

        r = sorted(q.results())
        assert len(r) == 1
        self.validate_allow(r[0], "test2s1", "test2t")

    def test_target_direct(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """RBAC rule query with exact, direct, target match."""
        q = RBACRuleQuery(
            compiled_policy, target="test10t", target_indirect=False, target_regex=False)

        r = sorted(q.results())
        assert len(r) == 1
        self.validate_allow(r[0], "test10s", "test10t")

    def test_target_direct_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """RBAC rule query with regex, direct, target match."""
        q = RBACRuleQuery(
            compiled_policy, target="test11t(1|3)", target_indirect=False, target_regex=True)

        r = sorted(q.results())
        assert len(r) == 1
        self.validate_allow(r[0], "test11s", "test11t1")

    def test_target_type(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """RBAC rule query with a type as target."""
        q = RBACRuleQuery(compiled_policy, target="test12t")

        r = sorted(q.results())
        assert len(r) == 1
        self.validate_rule(r[0], RRT.role_transition, "test12s", "test12t", "infoflow", "test12d")

    def test_class_list(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """RBAC rule query with object class list match."""
        q = RBACRuleQuery(
            compiled_policy, tclass=["infoflow3", "infoflow4"], tclass_regex=False)

        r = sorted(q.results())
        assert len(r) == 2
        self.validate_rule(r[0], RRT.role_transition, "test21", "system", "infoflow3", "test21d3")
        self.validate_rule(r[1], RRT.role_transition, "test21", "system", "infoflow4", "test21d2")

    def test_class_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """RBAC rule query with object class regex match."""
        q = RBACRuleQuery(compiled_policy, tclass="infoflow(5|6)", tclass_regex=True)

        r = sorted(q.results())
        assert len(r) == 2
        self.validate_rule(r[0], RRT.role_transition, "test22", "system", "infoflow5", "test22d2")
        self.validate_rule(r[1], RRT.role_transition, "test22", "system", "infoflow6", "test22d3")

    def test_default(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """RBAC rule query with exact default match."""
        q = RBACRuleQuery(
            compiled_policy, default="test30d", default_regex=False)

        r = sorted(q.results())
        assert len(r) == 1
        self.validate_rule(r[0], RRT.role_transition, "test30s", "system", "infoflow", "test30d")

    def test_default_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """RBAC rule query with regex default match."""
        q = RBACRuleQuery(
            compiled_policy, default="test31d(2|3)", default_regex=True)

        r = sorted(q.results())
        assert len(r) == 2
        self.validate_rule(r[0], RRT.role_transition, "test31s", "system", "infoflow7", "test31d3")
        self.validate_rule(r[1], RRT.role_transition, "test31s", "system", "process", "test31d2")

    def test_ruletype(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """RBAC rule query with rule type."""
        q = RBACRuleQuery(compiled_policy, ruletype=[RRT.allow])

        num = 0
        for num, r in enumerate(sorted(q.results()), start=1):
            assert r.ruletype == RRT.allow

        # this will have to be updated as number of
        # role allows change in the test policy
        assert num == 9
