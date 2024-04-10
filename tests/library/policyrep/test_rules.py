#
# SPDX-License-Identifier: GPL-2.0-only
#
from contextlib import suppress
import dataclasses
import enum

import pytest
import setools


@dataclasses.dataclass
class RuleTestCase:

    """
    Rule test case

    If the field is None, it is not supported by the rule type.
    """

    ruletype: enum.Enum
    source: str
    target: str
    statement: str
    type_: type  # the rule's policyrep class
    tclass: str | None = None
    xperm: str | None = None
    perms: set[str] | setools.IoctlSet | None = None
    default: str | None = None
    filename: str | None = None
    conditional: str | None = None


rule_test_data = [
    RuleTestCase(setools.RBACRuletype.allow, "role21a_r", "role21b_r",
                 type_=setools.RoleAllow, statement="allow role21a_r role21b_r;"),
    RuleTestCase(setools.RBACRuletype.role_transition, "role21b_r", "type30",
                 type_=setools.RoleTransition, default="role20_r", tclass="infoflow",
                 statement="role_transition role21b_r type30:infoflow role20_r;"),
    RuleTestCase(setools.MLSRuletype.range_transition, "type30", "system", tclass="infoflow7",
                 default="s0:c1 - s2:c0.c4", type_=setools.MLSRule,
                 statement="range_transition type30 system:infoflow7 s0:c1 - s2:c0.c4;"),
    RuleTestCase(setools.TERuletype.allow, "system", "type30", tclass="infoflow3",
                 perms=set(("null",)), type_=setools.AVRule,
                 statement="allow system type30:infoflow3 null;"),
    RuleTestCase(setools.TERuletype.auditallow, "type31c", "type31a", tclass="infoflow6",
                 perms=set(("hi_r", "hi_w")), type_=setools.AVRule,
                 statement="auditallow type31c type31a:infoflow6 { hi_r hi_w };"),
    RuleTestCase(setools.TERuletype.dontaudit, "type31c", "type31b", tclass="infoflow7",
                 perms=set(("super_w", "super_r")), type_=setools.AVRule, conditional="a_bool",
                 statement="dontaudit type31c type31b:infoflow7 "
                           "{ super_r super_w }; [ a_bool ]:True"),
    RuleTestCase(setools.TERuletype.type_transition, "type31b", "system", tclass="infoflow4",
                 default="type30", type_=setools.FileNameTERule, filename="the_filename",
                 statement="type_transition type31b system:infoflow4 type30 the_filename;"),
    RuleTestCase(setools.TERuletype.type_change, "type31c", "type31b", tclass="infoflow2",
                 default="system", type_=setools.TERule, conditional="a_bool",
                 statement="type_change type31c type31b:infoflow2 system; [ a_bool ]:False"),
    RuleTestCase(setools.TERuletype.allowxperm, "type30", "type31a", tclass="infoflow",
                 xperm="ioctl", perms=setools.IoctlSet((0x00ff,)), type_=setools.AVRuleXperm,
                 statement="allowxperm type30 type31a:infoflow ioctl 0x00ff;"),
    RuleTestCase(setools.TERuletype.auditallowxperm, "type31a", "type31b", tclass="infoflow",
                 xperm="ioctl", perms=setools.IoctlSet((1, 2, 3)), type_=setools.AVRuleXperm,
                 statement="auditallowxperm type31a type31b:infoflow ioctl 0x0001-0x0003;")]


@pytest.mark.obj_args("tests/library/policyrep/rules.conf")
@pytest.mark.parametrize("testcase", rule_test_data)
class TestRules:

    @pytest.fixture(autouse=True)
    def _get_rules(self, compiled_policy: setools.SELinuxPolicy) -> None:
        self.rules = dict[enum.Enum, setools.policyrep.PolicyRule]()
        self.rules |= {r.ruletype: r for r in compiled_policy.terules()}
        self.rules |= {r.ruletype: r for r in compiled_policy.rbacrules()}
        self.rules |= {r.ruletype: r for r in compiled_policy.mlsrules()}

    def test_ruletype(self, testcase: RuleTestCase) -> None:
        """Rule type"""
        rule = self.rules[testcase.ruletype]
        assert testcase.ruletype == rule.ruletype, f"{testcase.ruletype} != {rule.ruletype}"
        assert isinstance(rule, testcase.type_), f"{type(rule)}, {rule=}"

    def test_source_type(self, testcase: RuleTestCase) -> None:
        """Source object"""
        rule = self.rules[testcase.ruletype]
        assert testcase.source == rule.source, f"{testcase.source} != {rule.source}"

    def test_target_type(self, testcase: RuleTestCase) -> None:
        """Target object"""
        rule = self.rules[testcase.ruletype]
        assert testcase.target == rule.target, f"{testcase.target} != {rule.target}"

    def test_object_class(self, testcase: RuleTestCase) -> None:
        """Object class"""
        rule = self.rules[testcase.ruletype]
        if testcase.tclass is None:
            with pytest.raises(setools.exception.RuleUseError):
                rule.tclass
        else:
            assert testcase.tclass == rule.tclass, f"{testcase.tclass} != {rule.tclass}"

    def test_xperm_type(self, testcase: RuleTestCase) -> None:
        """Extended permission type"""
        rule = self.rules[testcase.ruletype]
        if testcase.xperm is None:
            assert rule.extended is False
            with pytest.raises(setools.exception.RuleUseError):
                rule.xperm_type
        else:
            assert rule.extended is True
            assert testcase.xperm == rule.xperm_type, f"{testcase.xperm} != {rule.xperm_type}"

    def test_permissions_or_default(self, testcase: RuleTestCase) -> None:
        """Test default/permissions"""
        assert not (testcase.default is not None and testcase.perms is not None), \
            f"Test case setup error {testcase=}"

        rule = self.rules[testcase.ruletype]
        if testcase.perms is not None:
            assert testcase.perms == rule.perms, f"{testcase.perms} != {rule.perms}"
            with pytest.raises(setools.exception.RuleUseError):
                rule.default
        elif testcase.default is not None:
            assert testcase.default == rule.default, f"{testcase.default} != {rule.default}"
            with pytest.raises(setools.exception.RuleUseError):
                rule.perms
        else:
            with pytest.raises(setools.exception.RuleUseError):
                rule.perms

            with pytest.raises(setools.exception.RuleUseError):
                rule.default

    def test_conditional(self, testcase: RuleTestCase) -> None:
        """Conditional expression"""
        rule = self.rules[testcase.ruletype]
        if testcase.conditional is None:
            with pytest.raises(setools.exception.RuleNotConditional):
                rule.conditional

            with pytest.raises(setools.exception.RuleNotConditional):
                rule.conditional_block
        else:
            assert testcase.conditional == rule.conditional, f"{rule.conditional}"
            assert isinstance(rule.conditional_block, bool), f"{rule.conditional_block}"

    def test_filename(self, testcase: RuleTestCase) -> None:
        """Filename"""
        rule = self.rules[testcase.ruletype]
        if testcase.filename is None:
            if rule.ruletype == setools.TERuletype.type_transition:
                with pytest.raises(setools.exception.TERuleNoFilename):
                    rule.filename
            else:
                with pytest.raises(setools.exception.RuleUseError):
                    rule.filename
        else:
            assert testcase.filename == rule.filename, f"{testcase.filename} != {rule.filename}"

    def test_statement(self, testcase: RuleTestCase) -> None:
        """Statement"""
        rule = self.rules[testcase.ruletype]
        assert testcase.statement == rule.statement(), \
            f"\"{testcase.statement}\" != \"{rule.statement()}\""

    def test_expand(self, testcase: RuleTestCase) -> None:
        """Expand"""
        rule = self.rules[testcase.ruletype]
        for expanded_rule in rule.expand():
            assert isinstance(expanded_rule, type(rule))
            if expanded_rule is rule:
                # the rule can't be expanded
                pass
            else:
                assert expanded_rule.origin == rule
                assert expanded_rule.source in rule.source
                assert expanded_rule.target in rule.target

                with suppress(setools.exception.RuleUseError):
                    assert expanded_rule.tclass == rule.tclass

                with suppress(setools.exception.RuleUseError):
                    assert expanded_rule.xperm_type == rule.xperm_type

                with suppress(setools.exception.RuleUseError):
                    assert expanded_rule.perms == rule.perms

                with suppress(setools.exception.RuleUseError):
                    assert expanded_rule.default == rule.default

                with suppress(setools.exception.RuleNotConditional):
                    assert expanded_rule.conditional == rule.conditional
                    assert expanded_rule.conditional_block == rule.conditional_block

                with suppress(setools.exception.RuleUseError):
                    assert expanded_rule.filename == rule.filename


@pytest.mark.obj_args("tests/library/policyrep/terule_issue74.conf")
class TestAVRuleXpermIssue74:

    """
    Regression test for xperm ranges starting with 0x00 not being loaded.
    https://github.com/SELinuxProject/setools/issues/74
    """

    def test_regression(self, compiled_policy: setools.SELinuxPolicy):
        """Regression test for GitHub issue 74."""
        rules = sorted(compiled_policy.terules())
        assert 2 == len(rules)

        # expect 2 rules:
        # allowxperm init_type_t init_type_t : unix_dgram_socket ioctl { 0x8910 };
        # allowxperm init_type_t init_type_t : unix_dgram_socket ioctl { 0x0-0xff };
        assert setools.IoctlSet(range(0x100)) == rules[0].perms, f"{rules[0].perms}"
        assert setools.IoctlSet([0x8910]) == rules[1].perms, f"{rules[1].perms}"
