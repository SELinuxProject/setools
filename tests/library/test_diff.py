# Copyright 2015-2016, Tresys Technology, LLC
# Copyright 2016, 2017, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: GPL-2.0-only
#
from dataclasses import astuple
from ipaddress import IPv6Address, IPv4Network, IPv6Network

import pytest
import setools
from setools import PolicyDifference, PortconProtocol, PortconRange
from setools import BoundsRuletype as BRT
from setools import ConstraintRuletype as CRT
from setools import DefaultRuletype as DRT
from setools import DefaultRangeValue as DRV
from setools import DefaultValue as DV
from setools import FSUseRuletype as FSURT
from setools import MLSRuletype as MRT
from setools import RBACRuletype as RRT
from setools import TERuletype as TRT

from . import util


@pytest.fixture(scope="class")
def analysis(policy_pair: tuple[setools.SELinuxPolicy, setools.SELinuxPolicy]) -> PolicyDifference:
    return PolicyDifference(*policy_pair)


@pytest.mark.obj_args("tests/library/diff_left.conf", "tests/library/diff_right.conf")
class TestPolicyDifference:

    """Policy difference tests."""

    #
    # Types
    #
    def test_added_types(self, analysis: setools.PolicyDifference) -> None:
        """Diff: added type"""
        assert set(["added_type"]) == analysis.added_types

    def test_removed_types(self, analysis: setools.PolicyDifference) -> None:
        """Diff: modified type"""
        assert set(["removed_type"]) == analysis.removed_types

    def test_modified_types_count(self, analysis: setools.PolicyDifference) -> None:
        """Diff: total modified types"""
        assert 6 == len(analysis.modified_types)

    def test_modified_types_remove_attr(self, analysis: setools.PolicyDifference) -> None:
        """Diff: modified type with removed attribute."""
        # modified_remove_attr
        analysis.modified_types.sort()
        type_ = analysis.modified_types[4]
        assert set(["an_attr"]) == type_.removed_attributes
        assert not type_.added_attributes
        assert not type_.matched_attributes
        assert not type_.modified_permissive
        assert not type_.permissive
        assert not type_.added_aliases
        assert not type_.removed_aliases
        assert not type_.matched_aliases

    def test_modified_types_remove_alias(self, analysis: setools.PolicyDifference) -> None:
        """Diff: modified type with removed alias."""
        # modified_remove_alias
        analysis.modified_types.sort()
        type_ = analysis.modified_types[3]
        assert set(["an_alias"]) == type_.removed_aliases
        assert not type_.added_attributes
        assert not type_.removed_attributes
        assert not type_.matched_attributes
        assert not type_.modified_permissive
        assert not type_.permissive
        assert not type_.added_aliases
        assert not type_.matched_aliases

    def test_modified_types_remove_permissive(self, analysis: setools.PolicyDifference) -> None:
        """Diff: modified type with removed permissve."""
        # modified_remove_permissive
        analysis.modified_types.sort()
        type_ = analysis.modified_types[5]
        assert not type_.added_attributes
        assert not type_.removed_attributes
        assert not type_.matched_attributes
        assert type_.modified_permissive
        assert type_.permissive
        assert not type_.added_aliases
        assert not type_.removed_aliases
        assert not type_.matched_aliases

    def test_modified_types_add_attr(self, analysis: setools.PolicyDifference) -> None:
        """Diff: modified type with added attribute."""
        # modified_add_attr
        analysis.modified_types.sort()
        type_ = analysis.modified_types[1]
        assert set(["an_attr"]) == type_.added_attributes
        assert not type_.removed_attributes
        assert not type_.matched_attributes
        assert not type_.modified_permissive
        assert not type_.permissive
        assert not type_.added_aliases
        assert not type_.removed_aliases
        assert not type_.matched_aliases

    def test_modified_types_add_alias(self, analysis: setools.PolicyDifference) -> None:
        """Diff: modified type with added alias."""
        # modified_add_alias
        analysis.modified_types.sort()
        type_ = analysis.modified_types[0]
        assert set(["an_alias"]) == type_.added_aliases
        assert not type_.added_attributes
        assert not type_.removed_attributes
        assert not type_.matched_attributes
        assert not type_.modified_permissive
        assert not type_.permissive
        assert not type_.removed_aliases
        assert not type_.matched_aliases

    def test_modified_types_add_permissive(self, analysis: setools.PolicyDifference) -> None:
        """Diff: modified type with added permissive."""
        # modified_add_permissive
        analysis.modified_types.sort()
        type_ = analysis.modified_types[2]
        assert not type_.added_attributes
        assert not type_.removed_attributes
        assert not type_.matched_attributes
        assert type_.modified_permissive
        assert not type_.permissive
        assert not type_.added_aliases
        assert not type_.removed_aliases
        assert not type_.matched_aliases

    #
    # Roles
    #
    def test_added_role(self, analysis: setools.PolicyDifference) -> None:
        """Diff: added role."""
        assert set(["added_role"]) == analysis.added_roles

    def test_removed_role(self, analysis: setools.PolicyDifference) -> None:
        """Diff: removed role."""
        assert set(["removed_role"]) == analysis.removed_roles

    def test_modified_role_count(self, analysis: setools.PolicyDifference) -> None:
        """Diff: modified role."""
        assert 2 == len(analysis.modified_roles)

    def test_modified_role_add_type(self, analysis: setools.PolicyDifference) -> None:
        """Diff: modified role with added type."""
        # modified_add_type
        analysis.modified_roles.sort()
        assert set(["system"]) == analysis.modified_roles[0].added_types
        assert not analysis.modified_roles[0].removed_types

    def test_modified_role_remove_type(self, analysis: setools.PolicyDifference) -> None:
        """Diff: modified role with removed type."""
        # modified_remove_type
        analysis.modified_roles.sort()
        assert set(["system"]) == analysis.modified_roles[1].removed_types
        assert not analysis.modified_roles[1].added_types

    #
    # Commons
    #
    def test_added_common(self, analysis: setools.PolicyDifference) -> None:
        """Diff: added common."""
        assert set(["added_common"]) == analysis.added_commons

    def test_removed_common(self, analysis: setools.PolicyDifference) -> None:
        """Diff: removed common."""
        assert set(["removed_common"]) == analysis.removed_commons

    def test_modified_common_count(self, analysis: setools.PolicyDifference) -> None:
        """Diff: modified common count."""
        assert 2 == len(analysis.modified_commons)

    def test_modified_common_add_perm(self, analysis: setools.PolicyDifference) -> None:
        """Diff: modified common with added perm."""
        # modified_add_perm
        analysis.modified_commons.sort()
        assert set(["added_perm"]) == analysis.modified_commons[0].added_perms
        assert not analysis.modified_commons[0].removed_perms

    def test_modified_common_remove_perm(self, analysis: setools.PolicyDifference) -> None:
        """Diff: modified common with removed perm."""
        # modified_remove_perm
        analysis.modified_commons.sort()
        assert set(["removed_perm"]) == analysis.modified_commons[1].removed_perms
        assert not analysis.modified_commons[1].added_perms

    #
    # Classes
    #
    def test_added_class(self, analysis: setools.PolicyDifference) -> None:
        """Diff: added class."""
        assert set(["added_class"]) == analysis.added_classes

    def test_removed_class(self, analysis: setools.PolicyDifference) -> None:
        """Diff: removed class."""
        assert set(["removed_class"]) == analysis.removed_classes

    def test_modified_class_count(self, analysis: setools.PolicyDifference) -> None:
        """Diff: modified class count."""
        assert 3 == len(analysis.modified_classes)

    def test_modified_class_add_perm(self, analysis: setools.PolicyDifference) -> None:
        """Diff: modified class with added perm."""
        # modified_add_perm
        analysis.modified_classes.sort()
        assert set(["added_perm"]) == analysis.modified_classes[0].added_perms
        assert not analysis.modified_classes[0].removed_perms

    def test_modified_class_remove_perm(self, analysis: setools.PolicyDifference) -> None:
        """Diff: modified class with removed perm."""
        # modified_remove_perm
        analysis.modified_classes.sort()
        assert set(["removed_perm"]) == analysis.modified_classes[2].removed_perms
        assert not analysis.modified_classes[2].added_perms

    def test_modified_class_change_common(self, analysis: setools.PolicyDifference) -> None:
        """Diff: modified class due to modified common."""
        # modified_change_common
        analysis.modified_classes.sort()
        assert set(["old_com"]) == analysis.modified_classes[1].removed_perms
        assert set(["new_com"]) == analysis.modified_classes[1].added_perms

    #
    # Allow rules
    #
    def test_added_allow_rules(self, analysis: setools.PolicyDifference) -> None:
        """Diff: added allow rules."""
        rules = sorted(analysis.added_allows)
        assert 5 == len(rules)

        # added rule with existing types
        util.validate_rule(rules[0], TRT.allow, "added_rule_source", "added_rule_target",
                           tclass="infoflow", perms=set(["med_w"]))

        # added rule with new type
        util.validate_rule(rules[1], TRT.allow, "added_type", "added_type", tclass="infoflow2",
                           perms=set(["med_w"]))

        # rule moved out of a conditional
        util.validate_rule(rules[2], TRT.allow, "move_from_bool", "move_from_bool",
                           tclass="infoflow4", perms=set(["hi_r"]))

        # rule moved into a conditional
        util.validate_rule(rules[3], TRT.allow, "move_to_bool", "move_to_bool",
                           tclass="infoflow4", perms=set(["hi_w"]), cond="move_to_bool_b",
                           cond_block=True)

        # rule moved from one conditional block to another (true to false)
        util.validate_rule(rules[4], TRT.allow, "system", "switch_block", tclass="infoflow6",
                           perms=set(["hi_r"]), cond="switch_block_b", cond_block=False)

    def test_removed_allow_rules(self, analysis: setools.PolicyDifference) -> None:
        """Diff: removed allow rules."""
        rules = sorted(analysis.removed_allows)
        assert 5 == len(rules)

        # rule moved out of a conditional
        util.validate_rule(rules[0], TRT.allow, "move_from_bool", "move_from_bool",
                           tclass="infoflow4", perms=set(["hi_r"]), cond="move_from_bool_b",
                           cond_block=True)

        # rule moved into a conditional
        util.validate_rule(rules[1], TRT.allow, "move_to_bool", "move_to_bool", tclass="infoflow4",
                           perms=set(["hi_w"]))

        # removed rule with existing types
        util.validate_rule(rules[2], TRT.allow, "removed_rule_source", "removed_rule_target",
                           tclass="infoflow", perms=set(["hi_r"]))

        # removed rule with new type
        util.validate_rule(rules[3], TRT.allow, "removed_type", "removed_type", tclass="infoflow3",
                           perms=set(["null"]))

        # rule moved from one conditional block to another (true to false)
        util.validate_rule(rules[4], TRT.allow, "system", "switch_block", tclass="infoflow6",
                           perms=set(["hi_r"]), cond="switch_block_b", cond_block=True)

    def test_modified_allow_rules(self, analysis: setools.PolicyDifference) -> None:
        """Diff: modified allow rules."""
        lst = sorted(analysis.modified_allows, key=lambda x: x.rule)
        assert 3 == len(lst)

        # add permissions
        rule, added_perms, removed_perms, matched_perms = astuple(lst[0])
        assert TRT.allow == rule.ruletype
        assert "modified_rule_add_perms" == rule.source
        assert "modified_rule_add_perms" == rule.target
        assert "infoflow" == rule.tclass
        assert set(["hi_w"]) == added_perms
        assert not removed_perms
        assert set(["hi_r"]) == matched_perms

        # add and remove permissions
        rule, added_perms, removed_perms, matched_perms = astuple(lst[1])
        assert TRT.allow == rule.ruletype
        assert "modified_rule_add_remove_perms" == rule.source
        assert "modified_rule_add_remove_perms" == rule.target
        assert "infoflow2" == rule.tclass
        assert set(["super_r"]) == added_perms
        assert set(["super_w"]) == removed_perms
        assert set(["low_w"]) == matched_perms

        # remove permissions
        rule, added_perms, removed_perms, matched_perms = astuple(lst[2])
        assert TRT.allow == rule.ruletype
        assert "modified_rule_remove_perms" == rule.source
        assert "modified_rule_remove_perms" == rule.target
        assert "infoflow" == rule.tclass
        assert not added_perms
        assert set(["low_r"]) == removed_perms
        assert set(["low_w"]) == matched_perms

    #
    # Auditallow rules
    #
    def test_added_auditallow_rules(self, analysis: setools.PolicyDifference) -> None:
        """Diff: added auditallow rules."""
        rules = sorted(analysis.added_auditallows)
        assert 5 == len(rules)

        # added rule with existing types
        util.validate_rule(rules[0], TRT.auditallow, "aa_added_rule_source",
                           "aa_added_rule_target", tclass="infoflow", perms=set(["med_w"]))

        # rule moved out of a conditional
        util.validate_rule(rules[1], TRT.auditallow, "aa_move_from_bool", "aa_move_from_bool",
                           tclass="infoflow4", perms=set(["hi_r"]))

        # rule moved into a conditional
        util.validate_rule(rules[2], TRT.auditallow, "aa_move_to_bool", "aa_move_to_bool",
                           tclass="infoflow4", perms=set(["hi_w"]), cond="aa_move_to_bool_b",
                           cond_block=True)

        # added rule with new type
        util.validate_rule(rules[3], TRT.auditallow, "added_type", "added_type", tclass="infoflow7",
                           perms=set(["super_none"]))

        # rule moved from one conditional block to another (true to false)
        util.validate_rule(rules[4], TRT.auditallow, "system", "aa_switch_block",
                           tclass="infoflow6", perms=set(["hi_r"]), cond="aa_switch_block_b",
                           cond_block=False)

    def test_removed_auditallow_rules(self, analysis: setools.PolicyDifference) -> None:
        """Diff: removed auditallow rules."""
        rules = sorted(analysis.removed_auditallows)
        assert 5 == len(rules)

        # rule moved out of a conditional
        util.validate_rule(rules[0], TRT.auditallow, "aa_move_from_bool", "aa_move_from_bool",
                           tclass="infoflow4", perms=set(["hi_r"]), cond="aa_move_from_bool_b",
                           cond_block=True)

        # rule moved into a conditional
        util.validate_rule(rules[1], TRT.auditallow, "aa_move_to_bool", "aa_move_to_bool",
                           tclass="infoflow4", perms=set(["hi_w"]))

        # removed rule with existing types
        util.validate_rule(rules[2], TRT.auditallow, "aa_removed_rule_source",
                           "aa_removed_rule_target", tclass="infoflow", perms=set(["hi_r"]))

        # removed rule with new type
        util.validate_rule(rules[3], TRT.auditallow, "removed_type", "removed_type",
                           tclass="infoflow7", perms=set(["super_unmapped"]))

        # rule moved from one conditional block to another (true to false)
        util.validate_rule(rules[4], TRT.auditallow, "system", "aa_switch_block",
                           tclass="infoflow6", perms=set(["hi_r"]), cond="aa_switch_block_b",
                           cond_block=True)

    def test_modified_auditallow_rules(self, analysis: setools.PolicyDifference) -> None:
        """Diff: modified auditallow rules."""
        lst = sorted(analysis.modified_auditallows, key=lambda x: x.rule)
        assert 3 == len(lst)

        # add permissions
        rule, added_perms, removed_perms, matched_perms = astuple(lst[0])
        assert TRT.auditallow == rule.ruletype
        assert "aa_modified_rule_add_perms" == rule.source
        assert "aa_modified_rule_add_perms" == rule.target
        assert "infoflow" == rule.tclass
        assert set(["hi_w"]) == added_perms
        assert not removed_perms
        assert set(["hi_r"]) == matched_perms

        # add and remove permissions
        rule, added_perms, removed_perms, matched_perms = astuple(lst[1])
        assert TRT.auditallow == rule.ruletype
        assert "aa_modified_rule_add_remove_perms" == rule.source
        assert "aa_modified_rule_add_remove_perms" == rule.target
        assert "infoflow2" == rule.tclass
        assert set(["super_r"]) == added_perms
        assert set(["super_w"]) == removed_perms
        assert set(["low_w"]) == matched_perms

        # remove permissions
        rule, added_perms, removed_perms, matched_perms = astuple(lst[2])
        assert TRT.auditallow == rule.ruletype
        assert "aa_modified_rule_remove_perms" == rule.source
        assert "aa_modified_rule_remove_perms" == rule.target
        assert "infoflow" == rule.tclass
        assert not added_perms
        assert set(["low_r"]) == removed_perms
        assert set(["low_w"]) == matched_perms

    #
    # Dontaudit rules
    #
    def test_added_dontaudit_rules(self, analysis: setools.PolicyDifference) -> None:
        """Diff: added dontaudit rules."""
        rules = sorted(analysis.added_dontaudits)
        assert 5 == len(rules)

        # added rule with new type
        util.validate_rule(rules[0], TRT.dontaudit, "added_type", "added_type", tclass="infoflow7",
                           perms=set(["super_none"]))

        # added rule with existing types
        util.validate_rule(rules[1], TRT.dontaudit, "da_added_rule_source", "da_added_rule_target",
                           tclass="infoflow", perms=set(["med_w"]))

        # rule moved out of a conditional
        util.validate_rule(rules[2], TRT.dontaudit, "da_move_from_bool", "da_move_from_bool",
                           tclass="infoflow4", perms=set(["hi_r"]))

        # rule moved into a conditional
        util.validate_rule(rules[3], TRT.dontaudit, "da_move_to_bool", "da_move_to_bool",
                           tclass="infoflow4", perms=set(["hi_w"]), cond="da_move_to_bool_b",
                           cond_block=True)

        # rule moved from one conditional block to another (true to false)
        util.validate_rule(rules[4], TRT.dontaudit, "system", "da_switch_block",
                           tclass="infoflow6", perms=set(["hi_r"]), cond="da_switch_block_b",
                           cond_block=False)

    def test_removed_dontaudit_rules(self, analysis: setools.PolicyDifference) -> None:
        """Diff: removed dontaudit rules."""
        rules = sorted(analysis.removed_dontaudits)
        assert 5 == len(rules)

        # rule moved out of a conditional
        util.validate_rule(rules[0], TRT.dontaudit, "da_move_from_bool", "da_move_from_bool",
                           tclass="infoflow4", perms=set(["hi_r"]), cond="da_move_from_bool_b",
                           cond_block=True)

        # rule moved into a conditional
        util.validate_rule(rules[1], TRT.dontaudit, "da_move_to_bool", "da_move_to_bool",
                           tclass="infoflow4", perms=set(["hi_w"]))

        # removed rule with existing types
        util.validate_rule(rules[2], TRT.dontaudit, "da_removed_rule_source",
                           "da_removed_rule_target", tclass="infoflow", perms=set(["hi_r"]))

        # removed rule with new type
        util.validate_rule(rules[3], TRT.dontaudit, "removed_type", "removed_type",
                           tclass="infoflow7", perms=set(["super_both"]))

        # rule moved from one conditional block to another (true to false)
        util.validate_rule(rules[4], TRT.dontaudit, "system", "da_switch_block",
                           tclass="infoflow6", perms=set(["hi_r"]), cond="da_switch_block_b",
                           cond_block=True)

    def test_modified_dontaudit_rules(self, analysis: setools.PolicyDifference) -> None:
        """Diff: modified dontaudit rules."""
        lst = sorted(analysis.modified_dontaudits, key=lambda x: x.rule)
        assert 3 == len(lst)

        # add permissions
        rule, added_perms, removed_perms, matched_perms = astuple(lst[0])
        assert TRT.dontaudit == rule.ruletype
        assert "da_modified_rule_add_perms" == rule.source
        assert "da_modified_rule_add_perms" == rule.target
        assert "infoflow" == rule.tclass
        assert set(["hi_w"]) == added_perms
        assert not removed_perms
        assert set(["hi_r"]) == matched_perms

        # add and remove permissions
        rule, added_perms, removed_perms, matched_perms = astuple(lst[1])
        assert TRT.dontaudit == rule.ruletype
        assert "da_modified_rule_add_remove_perms" == rule.source
        assert "da_modified_rule_add_remove_perms" == rule.target
        assert "infoflow2" == rule.tclass
        assert set(["super_r"]) == added_perms
        assert set(["super_w"]) == removed_perms
        assert set(["low_w"]) == matched_perms

        # remove permissions
        rule, added_perms, removed_perms, matched_perms = astuple(lst[2])
        assert TRT.dontaudit == rule.ruletype
        assert "da_modified_rule_remove_perms" == rule.source
        assert "da_modified_rule_remove_perms" == rule.target
        assert "infoflow" == rule.tclass
        assert not added_perms
        assert set(["low_r"]) == removed_perms
        assert set(["low_w"]) == matched_perms

    #
    # Neverallow rules
    #
    def test_added_neverallow_rules(self, analysis: setools.PolicyDifference) -> None:
        """Diff: added neverallow rules."""
        assert not analysis.added_neverallows
        # changed after dropping source policy support

        # rules = sorted(analysis.added_neverallows)
        # assert 2 == len(rules)

        # added rule with new type
        # util.validate_rule(rules[0], TRT.neverallow, "added_type", "added_type", "added_class",
        #                   set(["new_class_perm"]))

        # added rule with existing types
        # util.validate_rule(rules[1], TRT.neverallow, "na_added_rule_source",
        #                   "na_added_rule_target", "infoflow", set(["med_w"]))

    def test_removed_neverallow_rules(self, analysis: setools.PolicyDifference) -> None:
        """Diff: removed neverallow rules."""
        assert not analysis.removed_neverallows
        # changed after dropping source policy support
        # rules = sorted(analysis.removed_neverallows)
        # assert 2 == len(rules)

        # removed rule with existing types
        # util.validate_rule(rules[0], TRT.neverallow, "na_removed_rule_source",
        #                   "na_removed_rule_target", "infoflow", set(["hi_r"]))

        # removed rule with new type
        # util.validate_rule(rules[1], TRT.neverallow, "removed_type", "removed_type",
        #                   "removed_class", set(["null_perm"]))

    def test_modified_neverallow_rules(self, analysis: setools.PolicyDifference) -> None:
        """Diff: modified neverallow rules."""
        # changed after dropping source policy support
        assert not analysis.modified_neverallows
        # l = sorted(analysis.modified_neverallows, key=lambda x: x.rule)
        # assert 3 == len(l)
        #
        # # add permissions
        # rule, added_perms, removed_perms, matched_perms = l[0]
        # assert TRT.neverallow == rule.ruletype
        # assert "na_modified_rule_add_perms" == rule.source
        # assert "na_modified_rule_add_perms" == rule.target
        # assert "infoflow" == rule.tclass
        # assert set(["hi_w"]) == added_perms
        # assert not removed_perms
        # assert set(["hi_r"]) == matched_perms
        #
        # # add and remove permissions
        # rule, added_perms, removed_perms, matched_perms = l[1]
        # assert TRT.neverallow == rule.ruletype
        # assert "na_modified_rule_add_remove_perms" == rule.source
        # assert "na_modified_rule_add_remove_perms" == rule.target
        # assert "infoflow2" == rule.tclass
        # assert set(["super_r"]) == added_perms
        # assert set(["super_w"]) == removed_perms
        # assert set(["low_w"]) == matched_perms
        #
        # # remove permissions
        # rule, added_perms, removed_perms, matched_perms = l[2]
        # assert TRT.neverallow == rule.ruletype
        # assert "na_modified_rule_remove_perms" == rule.source
        # assert "na_modified_rule_remove_perms" == rule.target
        # assert "infoflow" == rule.tclass
        # assert not added_perms
        # assert set(["low_r"]) == removed_perms
        # assert set(["low_w"]) == matched_perms

    #
    # Type_transition rules
    #
    def test_added_type_transition_rules(self, analysis: setools.PolicyDifference) -> None:
        """Diff: added type_transition rules."""
        rules = sorted(analysis.added_type_transitions)
        assert 5 == len(rules)

        # added rule with new type
        util.validate_rule(rules[0], TRT.type_transition, "added_type", "system",
                           tclass="infoflow4", default="system")

        # rule moved from one conditional block to another (true to false)
        util.validate_rule(rules[1], TRT.type_transition, "system", "tt_switch_block",
                           tclass="infoflow6", default="system", cond="tt_switch_block_b",
                           cond_block=False)

        # added rule with existing types
        util.validate_rule(rules[2], TRT.type_transition, "tt_added_rule_source",
                           "tt_added_rule_target", tclass="infoflow", default="system")

        # rule moved out of a conditional
        util.validate_rule(rules[3], TRT.type_transition, "tt_move_from_bool", "system",
                           tclass="infoflow4", default="system")

        # rule moved into a conditional
        util.validate_rule(rules[4], TRT.type_transition, "tt_move_to_bool", "system",
                           tclass="infoflow3", default="system", cond="tt_move_to_bool_b",
                           cond_block=True)

    def test_removed_type_transition_rules(self, analysis: setools.PolicyDifference) -> None:
        """Diff: removed type_transition rules."""
        rules = sorted(analysis.removed_type_transitions)
        assert 5 == len(rules)

        # removed rule with new type
        util.validate_rule(rules[0], TRT.type_transition, "removed_type", "system",
                           tclass="infoflow4", default="system")

        # rule moved from one conditional block to another (true to false)
        util.validate_rule(rules[1], TRT.type_transition, "system", "tt_switch_block",
                           tclass="infoflow6", default="system", cond="tt_switch_block_b",
                           cond_block=True)

        # rule moved out of a conditional
        util.validate_rule(rules[2], TRT.type_transition, "tt_move_from_bool", "system",
                           tclass="infoflow4", default="system", cond="tt_move_from_bool_b",
                           cond_block=True)

        # rule moved into a conditional
        util.validate_rule(rules[3], TRT.type_transition, "tt_move_to_bool", "system",
                           tclass="infoflow3", default="system")

        # removed rule with existing types
        util.validate_rule(rules[4], TRT.type_transition, "tt_removed_rule_source",
                           "tt_removed_rule_target", tclass="infoflow", default="system")

    def test_modified_type_transition_rules(self, analysis: setools.PolicyDifference) -> None:
        """Diff: modified type_transition rules."""
        lst = sorted(analysis.modified_type_transitions, key=lambda x: x.rule)
        assert 1 == len(lst)

        rule, added_default, removed_default = astuple(lst[0])
        assert TRT.type_transition == rule.ruletype
        assert "tt_matched_source" == rule.source
        assert "system" == rule.target
        assert "infoflow" == rule.tclass
        assert "tt_new_type" == added_default
        assert "tt_old_type" == removed_default

    #
    # Type_change rules
    #
    def test_added_type_change_rules(self, analysis: setools.PolicyDifference) -> None:
        """Diff: added type_change rules."""
        rules = sorted(analysis.added_type_changes)
        assert 5 == len(rules)

        # added rule with new type
        util.validate_rule(rules[0], TRT.type_change, "added_type", "system", tclass="infoflow4",
                           default="system")

        # rule moved from one conditional block to another (true to false)
        util.validate_rule(rules[1], TRT.type_change, "system", "tc_switch_block",
                           tclass="infoflow6", default="system", cond="tc_switch_block_b",
                           cond_block=False)

        # added rule with existing types
        util.validate_rule(rules[2], TRT.type_change, "tc_added_rule_source",
                           "tc_added_rule_target", tclass="infoflow", default="system")

        # rule moved out of a conditional
        util.validate_rule(rules[3], TRT.type_change, "tc_move_from_bool", "system",
                           tclass="infoflow4", default="system")

        # rule moved into a conditional
        util.validate_rule(rules[4], TRT.type_change, "tc_move_to_bool", "system",
                           tclass="infoflow3", default="system", cond="tc_move_to_bool_b",
                           cond_block=True)

    def test_removed_type_change_rules(self, analysis: setools.PolicyDifference) -> None:
        """Diff: removed type_change rules."""
        rules = sorted(analysis.removed_type_changes)
        assert 5 == len(rules)

        # removed rule with new type
        util.validate_rule(rules[0], TRT.type_change, "removed_type", "system", tclass="infoflow4",
                           default="system")

        # rule moved from one conditional block to another (true to false)
        util.validate_rule(rules[1], TRT.type_change, "system", "tc_switch_block",
                           tclass="infoflow6", default="system", cond="tc_switch_block_b",
                           cond_block=True)

        # rule moved out of a conditional
        util.validate_rule(rules[2], TRT.type_change, "tc_move_from_bool", "system",
                           tclass="infoflow4", default="system", cond="tc_move_from_bool_b",
                           cond_block=True)

        # rule moved into a conditional
        util.validate_rule(rules[3], TRT.type_change, "tc_move_to_bool", "system",
                           tclass="infoflow3", default="system")

        # removed rule with existing types
        util.validate_rule(rules[4], TRT.type_change, "tc_removed_rule_source",
                           "tc_removed_rule_target", tclass="infoflow", default="system")

    def test_modified_type_change_rules(self, analysis: setools.PolicyDifference) -> None:
        """Diff: modified type_change rules."""
        lst = sorted(analysis.modified_type_changes, key=lambda x: x.rule)
        assert 1 == len(lst)

        rule, added_default, removed_default = astuple(lst[0])
        assert TRT.type_change == rule.ruletype
        assert "tc_matched_source" == rule.source
        assert "system" == rule.target
        assert "infoflow" == rule.tclass
        assert "tc_new_type" == added_default
        assert "tc_old_type" == removed_default

    #
    # Type_member rules
    #
    def test_added_type_member_rules(self, analysis: setools.PolicyDifference) -> None:
        """Diff: added type_member rules."""
        rules = sorted(analysis.added_type_members)
        assert 5 == len(rules)

        # added rule with new type
        util.validate_rule(rules[0], TRT.type_member, "added_type", "system", tclass="infoflow4",
                           default="system")

        # rule moved from one conditional block to another (true to false)
        util.validate_rule(rules[1], TRT.type_member, "system", "tm_switch_block",
                           tclass="infoflow6", default="system", cond="tm_switch_block_b",
                           cond_block=False)

        # added rule with existing types
        util.validate_rule(rules[2], TRT.type_member, "tm_added_rule_source",
                           "tm_added_rule_target", tclass="infoflow", default="system")

        # rule moved out of a conditional
        util.validate_rule(rules[3], TRT.type_member, "tm_move_from_bool", "system",
                           tclass="infoflow4", default="system")

        # rule moved into a conditional
        util.validate_rule(rules[4], TRT.type_member, "tm_move_to_bool", "system",
                           tclass="infoflow3", default="system", cond="tm_move_to_bool_b",
                           cond_block=True)

    def test_removed_type_member_rules(self, analysis: setools.PolicyDifference) -> None:
        """Diff: removed type_member rules."""
        rules = sorted(analysis.removed_type_members)
        assert 5 == len(rules)

        # removed rule with new type
        util.validate_rule(rules[0], TRT.type_member, "removed_type", "system", tclass="infoflow4",
                           default="system")

        # rule moved from one conditional block to another (true to false)
        util.validate_rule(rules[1], TRT.type_member, "system", "tm_switch_block",
                           tclass="infoflow6", default="system", cond="tm_switch_block_b",
                           cond_block=True)

        # rule moved out of a conditional
        util.validate_rule(rules[2], TRT.type_member, "tm_move_from_bool", "system",
                           tclass="infoflow4", default="system", cond="tm_move_from_bool_b",
                           cond_block=True)

        # rule moved into a conditional
        util.validate_rule(rules[3], TRT.type_member, "tm_move_to_bool", "system",
                           tclass="infoflow3", default="system")

        # removed rule with existing types
        util.validate_rule(rules[4], TRT.type_member, "tm_removed_rule_source",
                           "tm_removed_rule_target", tclass="infoflow", default="system")

    def test_modified_type_member_rules(self, analysis: setools.PolicyDifference) -> None:
        """Diff: modified type_member rules."""
        lst = sorted(analysis.modified_type_members, key=lambda x: x.rule)
        assert 1 == len(lst)

        rule, added_default, removed_default = astuple(lst[0])
        assert TRT.type_member == rule.ruletype
        assert "tm_matched_source" == rule.source
        assert "system" == rule.target
        assert "infoflow" == rule.tclass
        assert "tm_new_type" == added_default
        assert "tm_old_type" == removed_default

    #
    # Range_transition rules
    #
    def test_added_range_transition_rules(self, analysis: setools.PolicyDifference) -> None:
        """Diff: added range_transition rules."""
        rules = sorted(analysis.added_range_transitions)
        assert 2 == len(rules)

        # added rule with new type
        util.validate_rule(rules[0], MRT.range_transition, "added_type", "system",
                           tclass="infoflow4", default="s3")

        # added rule with existing types
        util.validate_rule(rules[1], MRT.range_transition, "rt_added_rule_source",
                           "rt_added_rule_target", tclass="infoflow", default="s3")

    def test_removed_range_transition_rules(self, analysis: setools.PolicyDifference) -> None:
        """Diff: removed range_transition rules."""
        rules = sorted(analysis.removed_range_transitions)
        assert 2 == len(rules)

        # removed rule with new type
        util.validate_rule(rules[0], MRT.range_transition, "removed_type", "system",
                           tclass="infoflow4", default="s1")

        # removed rule with existing types
        util.validate_rule(rules[1], MRT.range_transition, "rt_removed_rule_source",
                           "rt_removed_rule_target", tclass="infoflow", default="s1")

    def test_modified_range_transition_rules(self, analysis: setools.PolicyDifference) -> None:
        """Diff: modified range_transition rules."""
        lst = sorted(analysis.modified_range_transitions, key=lambda x: x.rule)
        assert 1 == len(lst)

        rule, added_default, removed_default = astuple(lst[0])
        assert MRT.range_transition == rule.ruletype
        assert "rt_matched_source" == rule.source
        assert "system" == rule.target
        assert "infoflow" == rule.tclass
        assert "s0:c0,c4 - s1:c0.c2,c4" == added_default
        assert "s2:c0 - s3:c0.c2" == removed_default

    #
    # Role allow rules
    #
    def test_added_role_allow_rules(self, analysis: setools.PolicyDifference) -> None:
        """Diff: added role_allow rules."""
        rules = sorted(analysis.added_role_allows)
        assert 2 == len(rules)

        # added rule with existing roles
        assert RRT.allow == rules[0].ruletype
        assert "added_role" == rules[0].source
        assert "system" == rules[0].target

        # added rule with new roles
        assert RRT.allow == rules[1].ruletype
        assert "added_rule_source_r" == rules[1].source
        assert "added_rule_target_r" == rules[1].target

    def test_removed_role_allow_rules(self, analysis: setools.PolicyDifference) -> None:
        """Diff: removed role_allow rules."""
        rules = sorted(analysis.removed_role_allows)
        assert 2 == len(rules)

        # removed rule with removed role
        assert RRT.allow == rules[0].ruletype
        assert "removed_role" == rules[0].source
        assert "system" == rules[0].target

        # removed rule with existing roles
        assert RRT.allow == rules[1].ruletype
        assert "removed_rule_source_r" == rules[1].source
        assert "removed_rule_target_r" == rules[1].target

    #
    # Role_transition rules
    #
    def test_added_role_transition_rules(self, analysis: setools.PolicyDifference) -> None:
        """Diff: added role_transition rules."""
        rules = sorted(analysis.added_role_transitions)
        assert 2 == len(rules)

        # added rule with new role
        util.validate_rule(rules[0], RRT.role_transition, "added_role", "system",
                           tclass="infoflow4", default="system")

        # added rule with existing roles
        util.validate_rule(rules[1], RRT.role_transition, "role_tr_added_rule_source",
                           "role_tr_added_rule_target", tclass="infoflow6", default="system")

    def test_removed_role_transition_rules(self, analysis: setools.PolicyDifference) -> None:
        """Diff: removed role_transition rules."""
        rules = sorted(analysis.removed_role_transitions)
        assert 2 == len(rules)

        # removed rule with new role
        util.validate_rule(rules[0], RRT.role_transition, "removed_role", "system",
                           tclass="infoflow4", default="system")

        # removed rule with existing roles
        util.validate_rule(rules[1], RRT.role_transition, "role_tr_removed_rule_source",
                           "role_tr_removed_rule_target", tclass="infoflow5", default="system")

    def test_modified_role_transition_rules(self, analysis: setools.PolicyDifference) -> None:
        """Diff: modified role_transition rules."""
        lst = sorted(analysis.modified_role_transitions, key=lambda x: x.rule)
        assert 1 == len(lst)

        rule, added_default, removed_default = astuple(lst[0])
        assert RRT.role_transition == rule.ruletype
        assert "role_tr_matched_source" == rule.source
        assert "role_tr_matched_target" == rule.target
        assert "infoflow3" == rule.tclass
        assert "role_tr_new_role" == added_default
        assert "role_tr_old_role" == removed_default

    #
    # Users
    #
    def test_added_user(self, analysis: setools.PolicyDifference) -> None:
        """Diff: added user."""
        assert set(["added_user"]) == analysis.added_users

    def test_removed_user(self, analysis: setools.PolicyDifference) -> None:
        """Diff: removed user."""
        assert set(["removed_user"]) == analysis.removed_users

    def test_modified_user_count(self, analysis: setools.PolicyDifference) -> None:
        """Diff: modified user count."""
        assert 4 == len(analysis.modified_users)

    def test_modified_user_add_role(self, analysis: setools.PolicyDifference) -> None:
        """Diff: modified user with added role."""
        # modified_add_role
        analysis.modified_users.sort()
        assert set(["added_role"]) == analysis.modified_users[0].added_roles
        assert not analysis.modified_users[0].removed_roles

    def test_modified_user_remove_role(self, analysis: setools.PolicyDifference) -> None:
        """Diff: modified user with removed role."""
        # modified_remove_role
        analysis.modified_users.sort()
        assert set(["removed_role"]) == analysis.modified_users[3].removed_roles
        assert not analysis.modified_users[3].added_roles

    def test_modified_user_change_level(self, analysis: setools.PolicyDifference) -> None:
        """Diff: modified user due to modified default level."""
        # modified_change_level
        analysis.modified_users.sort()
        assert "s2:c0" == analysis.modified_users[1].removed_level
        assert "s2:c1" == analysis.modified_users[1].added_level

    def test_modified_user_change_range(self, analysis: setools.PolicyDifference) -> None:
        """Diff: modified user due to modified range."""
        # modified_change_range
        analysis.modified_users.sort()
        assert "s3:c1 - s3:c1.c3" == analysis.modified_users[2].removed_range
        assert "s3:c1 - s3:c1.c4" == analysis.modified_users[2].added_range

    #
    # Type attributes
    #
    def test_added_type_attribute(self, analysis: setools.PolicyDifference) -> None:
        """Diff: added type attribute."""
        assert set(["added_attr"]) == analysis.added_type_attributes

    def test_removed_type_attribute(self, analysis: setools.PolicyDifference) -> None:
        """Diff: removed type attribute."""
        assert set(["removed_attr"]) == analysis.removed_type_attributes

    def test_modified_type_attribute(self, analysis: setools.PolicyDifference) -> None:
        """Diff: modified type attribute."""
        assert 1 == len(analysis.modified_type_attributes)
        assert set(["modified_add_attr"]) == analysis.modified_type_attributes[0].added_types
        assert set(["modified_remove_attr"]) == analysis.modified_type_attributes[0].removed_types

    #
    # Booleans
    #
    def test_added_boolean(self, analysis: setools.PolicyDifference) -> None:
        """Diff: added boolean."""
        assert set(["added_bool"]) == analysis.added_booleans

    def test_removed_boolean(self, analysis: setools.PolicyDifference) -> None:
        """Diff: removed boolean."""
        assert set(["removed_bool"]) == analysis.removed_booleans

    def test_modified_boolean(self, analysis: setools.PolicyDifference) -> None:
        """Diff: modified boolean."""
        assert 1 == len(analysis.modified_booleans)
        assert analysis.modified_booleans[0].added_state
        assert not analysis.modified_booleans[0].removed_state

    #
    # Categories
    #
    def test_added_category(self, analysis: setools.PolicyDifference) -> None:
        """Diff: added category."""
        assert set(["c6"]) == analysis.added_categories

    def test_removed_category(self, analysis: setools.PolicyDifference) -> None:
        """Diff: removed category."""
        assert set(["c5"]) == analysis.removed_categories

    def test_modified_category(self, analysis: setools.PolicyDifference) -> None:
        """Diff: modified categories."""
        assert 2 == len(analysis.modified_categories)
        analysis.modified_categories.sort()

        # add alias on c1
        assert set(["foo"]) == analysis.modified_categories[1].added_aliases
        assert not analysis.modified_categories[1].removed_aliases

        # remove alias on c0
        assert not analysis.modified_categories[0].added_aliases
        assert set(["eggs"]) == analysis.modified_categories[0].removed_aliases

    #
    # Sensitivity
    #
    def test_added_sensitivities(self, analysis: setools.PolicyDifference) -> None:
        """Diff: added sensitivities."""
        assert set(["s46"]) == analysis.added_sensitivities

    def test_removed_sensitivities(self, analysis: setools.PolicyDifference) -> None:
        """Diff: removed sensitivities."""
        assert set(["s47"]) == analysis.removed_sensitivities

    def test_modified_sensitivities(self, analysis: setools.PolicyDifference) -> None:
        """Diff: modified sensitivities."""
        assert 2 == len(analysis.modified_sensitivities)
        analysis.modified_sensitivities.sort()

        # add alias to s1
        assert set(["al4"]) == analysis.modified_sensitivities[1].added_aliases
        assert not analysis.modified_sensitivities[1].removed_aliases

        # remove alias from s0
        assert not analysis.modified_sensitivities[0].added_aliases
        assert set(["al2"]) == analysis.modified_sensitivities[0].removed_aliases

    #
    # Initial SIDs
    #
    def test_added_initialsids(self, analysis: setools.PolicyDifference) -> None:
        """Diff: added initialsids."""
        assert set(["file_labels"]) == analysis.added_initialsids

    @pytest.mark.skip("Moved to PolicyDifferenceRmIsidTest.")
    def test_removed_initialsids(self, analysis: setools.PolicyDifference) -> None:
        """Diff: removed initialsids."""
        assert set(["removed_sid"]) == analysis.removed_initialsids

    def test_modified_initialsids(self, analysis: setools.PolicyDifference) -> None:
        """Diff: modified initialsids."""
        assert 1 == len(analysis.modified_initialsids)
        assert "system:system:system:s0" == analysis.modified_initialsids[0].added_context
        assert "removed_user:system:system:s0" == analysis.modified_initialsids[0].removed_context

    #
    # fs_use_*
    #
    def test_added_fs_uses(self, analysis: setools.PolicyDifference) -> None:
        """Diff: added fs_uses."""
        lst = sorted(analysis.added_fs_uses)
        assert 1 == len(lst)

        rule = lst[0]
        assert FSURT.fs_use_xattr == rule.ruletype
        assert "added_fsuse" == rule.fs
        assert "system:object_r:system:s0" == rule.context

    def test_removed_fs_uses(self, analysis: setools.PolicyDifference) -> None:
        """Diff: removed fs_uses."""
        lst = sorted(analysis.removed_fs_uses)
        assert 1 == len(lst)

        rule = lst[0]
        assert FSURT.fs_use_task == rule.ruletype
        assert "removed_fsuse" == rule.fs
        assert "system:object_r:system:s0" == rule.context

    def test_modified_fs_uses(self, analysis: setools.PolicyDifference) -> None:
        """Diff: modified fs_uses."""
        lst = sorted(analysis.modified_fs_uses, key=lambda x: x.rule)
        assert 1 == len(lst)

        rule, added_context, removed_context = astuple(lst[0])
        assert FSURT.fs_use_trans == rule.ruletype
        assert "modified_fsuse" == rule.fs
        assert "added_user:object_r:system:s1" == added_context
        assert "removed_user:object_r:system:s0" == removed_context

    #
    # genfscon
    #
    def test_added_genfscons(self, analysis: setools.PolicyDifference) -> None:
        """Diff: added genfscons."""
        lst = sorted(analysis.added_genfscons)
        assert 2 == len(lst)

        rule = lst[0]
        assert "added_genfs" == rule.fs
        assert "/" == rule.path
        assert "added_user:object_r:system:s0" == rule.context

        rule = lst[1]
        assert "change_path" == rule.fs
        assert "/new" == rule.path
        assert "system:object_r:system:s0" == rule.context

    def test_removed_genfscons(self, analysis: setools.PolicyDifference) -> None:
        """Diff: removed genfscons."""
        lst = sorted(analysis.removed_genfscons)
        assert 2 == len(lst)

        rule = lst[0]
        assert "change_path" == rule.fs
        assert "/old" == rule.path
        assert "system:object_r:system:s0" == rule.context

        rule = lst[1]
        assert "removed_genfs" == rule.fs
        assert "/" == rule.path
        assert "system:object_r:system:s0" == rule.context

    def test_modified_genfscons(self, analysis: setools.PolicyDifference) -> None:
        """Diff: modified genfscons."""
        lst = sorted(analysis.modified_genfscons, key=lambda x: x.rule)
        assert 1 == len(lst)

        rule, added_context, removed_context = astuple(lst[0])
        assert "modified_genfs" == rule.fs
        assert "/" == rule.path
        assert "added_user:object_r:system:s0" == added_context
        assert "removed_user:object_r:system:s0" == removed_context

    #
    # level decl
    #
    def test_added_levels(self, analysis: setools.PolicyDifference) -> None:
        """Diff: added levels."""
        lst = sorted(analysis.added_levels)
        assert 1 == len(lst)
        assert "s46:c0.c4" == lst[0]

    def test_removed_levels(self, analysis: setools.PolicyDifference) -> None:
        """Diff: removed levels."""
        lst = sorted(analysis.removed_levels)
        assert 1 == len(lst)
        assert "s47:c0.c4" == lst[0]

    def test_modified_levels(self, analysis: setools.PolicyDifference) -> None:
        """Diff: modified levels."""
        lst = sorted(analysis.modified_levels)
        assert 2 == len(lst)

        level = lst[0]
        assert "s40" == level.level.sensitivity
        assert set(["c3"]) == level.added_categories
        assert not level.removed_categories

        level = lst[1]
        assert "s41" == level.level.sensitivity
        assert not level.added_categories
        assert set(["c4"]) == level.removed_categories

    #
    # netifcon
    #
    def test_added_netifcons(self, analysis: setools.PolicyDifference) -> None:
        """Diff: added netifcons."""
        lst = sorted(analysis.added_netifcons)
        assert 1 == len(lst)

        rule = lst[0]
        assert "added_netif" == rule.netif
        assert "system:object_r:system:s0" == rule.context
        assert "system:object_r:system:s0" == rule.packet

    def test_removed_netifcons(self, analysis: setools.PolicyDifference) -> None:
        """Diff: removed netifcons."""
        lst = sorted(analysis.removed_netifcons)
        assert 1 == len(lst)

        rule = lst[0]
        assert "removed_netif" == rule.netif
        assert "system:object_r:system:s0" == rule.context
        assert "system:object_r:system:s0" == rule.packet

    def test_modified_netifcons(self, analysis: setools.PolicyDifference) -> None:
        """Diff: modified netifcons."""
        lst = sorted(analysis.modified_netifcons, key=lambda x: x.rule)
        assert 3 == len(lst)

        # modified both contexts
        rule, added_context, removed_context, added_packet, removed_packet = astuple(lst[0])
        assert "mod_both_netif" == rule.netif
        assert "added_user:object_r:system:s0" == added_context
        assert "removed_user:object_r:system:s0" == removed_context
        assert "added_user:object_r:system:s0" == added_packet
        assert "removed_user:object_r:system:s0" == removed_packet

        # modified context
        rule, added_context, removed_context, added_packet, removed_packet = astuple(lst[1])
        assert "mod_ctx_netif" == rule.netif
        assert "added_user:object_r:system:s0" == added_context
        assert "removed_user:object_r:system:s0" == removed_context
        assert added_packet is None
        assert removed_packet is None

        # modified packet context
        rule, added_context, removed_context, added_packet, removed_packet = astuple(lst[2])
        assert "mod_pkt_netif" == rule.netif
        assert added_context is None
        assert removed_context is None
        assert "added_user:object_r:system:s0" == added_packet
        assert "removed_user:object_r:system:s0" == removed_packet

    #
    # nodecons
    #
    def test_added_nodecons(self, analysis: setools.PolicyDifference) -> None:
        """Diff: added nodecons."""
        lst = sorted(analysis.added_nodecons)
        assert 4 == len(lst)

        # new IPv4
        nodecon = lst[0]
        assert IPv4Network("124.0.0.0/8") == nodecon.network

        # changed IPv4 netmask
        nodecon = lst[1]
        assert IPv4Network("125.0.0.0/16") == nodecon.network

        # new IPv6
        nodecon = lst[2]
        assert IPv6Network("ff04::/62") == nodecon.network

        # changed IPv6 netmask
        nodecon = lst[3]
        assert IPv6Network("ff05::/60") == nodecon.network

    def test_removed_nodecons(self, analysis: setools.PolicyDifference) -> None:
        """Diff: removed nodecons."""
        lst = sorted(analysis.removed_nodecons)
        assert 4 == len(lst)

        # new IPv4
        nodecon = lst[0]
        assert IPv4Network("122.0.0.0/8") == nodecon.network

        # changed IPv4 netmask
        nodecon = lst[1]
        assert IPv4Network("125.0.0.0/8") == nodecon.network

        # new IPv6
        nodecon = lst[2]
        assert IPv6Network("ff02::/62") == nodecon.network

        # changed IPv6 netmask
        nodecon = lst[3]
        assert IPv6Network("ff05::/62") == nodecon.network

    def test_modified_nodecons(self, analysis: setools.PolicyDifference) -> None:
        """Diff: modified nodecons."""
        lst = sorted(analysis.modified_nodecons, key=lambda x: x.rule)
        assert 2 == len(lst)

        # changed IPv4
        nodecon, added_context, removed_context = astuple(lst[0])
        assert IPv4Network("123.0.0.0/8") == nodecon.network
        assert "modified_change_level:object_r:system:s2:c0" == added_context
        assert "modified_change_level:object_r:system:s2:c1" == removed_context

        # changed IPv6
        nodecon, added_context, removed_context = astuple(lst[1])
        assert IPv6Network("ff03::/62") == nodecon.network
        assert "modified_change_level:object_r:system:s2:c1" == added_context
        assert "modified_change_level:object_r:system:s2:c0.c1" == removed_context

    #
    # Policy capabilities
    #
    def test_added_polcaps(self, analysis: setools.PolicyDifference) -> None:
        """Diff: added polcaps."""
        assert set(["always_check_network"]) == analysis.added_polcaps

    def test_removed_polcaps(self, analysis: setools.PolicyDifference) -> None:
        """Diff: removed polcaps."""
        assert set(["network_peer_controls"]) == analysis.removed_polcaps

    #
    # portcons
    #
    def test_added_portcons(self, analysis: setools.PolicyDifference) -> None:
        """Diff: added portcons."""
        lst = sorted(analysis.added_portcons)
        assert 2 == len(lst)

        portcon = lst[0]
        assert PortconProtocol.tcp == portcon.protocol
        assert PortconRange(2024, 2026) == portcon.ports

        portcon = lst[1]
        assert PortconProtocol.udp == portcon.protocol
        assert PortconRange(2024, 2024) == portcon.ports

    def test_removed_portcons(self, analysis: setools.PolicyDifference) -> None:
        """Diff: removed portcons."""
        lst = sorted(analysis.removed_portcons)
        assert 2 == len(lst)

        portcon = lst[0]
        assert PortconProtocol.tcp == portcon.protocol
        assert PortconRange(1024, 1026) == portcon.ports

        portcon = lst[1]
        assert PortconProtocol.udp == portcon.protocol
        assert PortconRange(1024, 1024) == portcon.ports

    def test_modified_portcons(self, analysis: setools.PolicyDifference) -> None:
        """Diff: modified portcons."""
        lst = sorted(analysis.modified_portcons, key=lambda x: x.rule)
        assert 2 == len(lst)

        portcon, added_context, removed_context = astuple(lst[0])
        assert PortconProtocol.tcp == portcon.protocol
        assert PortconRange(3024, 3026) == portcon.ports
        assert "added_user:object_r:system:s1" == added_context
        assert "removed_user:object_r:system:s0" == removed_context

        portcon, added_context, removed_context = astuple(lst[1])
        assert PortconProtocol.udp == portcon.protocol
        assert PortconRange(3024, 3024) == portcon.ports
        assert "added_user:object_r:system:s1" == added_context
        assert "removed_user:object_r:system:s0" == removed_context

    #
    # defaults
    #
    def test_added_defaults(self, analysis: setools.PolicyDifference) -> None:
        """Diff: added defaults."""
        lst = sorted(analysis.added_defaults)
        assert 2 == len(lst)

        default = lst[0]
        assert DRT.default_range == default.ruletype
        assert "infoflow2" == default.tclass

        default = lst[1]
        assert DRT.default_user == default.ruletype
        assert "infoflow2" == default.tclass

    def test_removed_defaults(self, analysis: setools.PolicyDifference) -> None:
        """Diff: removed defaults."""
        lst = sorted(analysis.removed_defaults)
        assert 2 == len(lst)

        default = lst[0]
        assert DRT.default_range == default.ruletype
        assert "infoflow3" == default.tclass

        default = lst[1]
        assert DRT.default_role == default.ruletype
        assert "infoflow3" == default.tclass

    def test_modified_defaults(self, analysis: setools.PolicyDifference) -> None:
        """Diff: modified defaults."""
        lst = sorted(analysis.modified_defaults, key=lambda x: x.rule)
        assert 4 == len(lst)

        default, added_default, removed_default, added_range, removed_range = astuple(lst[0])
        assert DRT.default_range == default.ruletype
        assert "infoflow4" == default.tclass
        assert DV.target == added_default
        assert DV.source == removed_default
        assert added_range is None
        assert removed_range is None

        default, added_default, removed_default, added_range, removed_range = astuple(lst[1])
        assert DRT.default_range == default.ruletype
        assert "infoflow5" == default.tclass
        assert added_default is None
        assert removed_default is None
        assert DRV.high == added_range
        assert DRV.low == removed_range

        default, added_default, removed_default, added_range, removed_range = astuple(lst[2])
        assert DRT.default_range == default.ruletype
        assert "infoflow6" == default.tclass
        assert DV.target == added_default
        assert DV.source == removed_default
        assert DRV.low == added_range
        assert DRV.high == removed_range

        default, added_default, removed_default, added_range, removed_range = astuple(lst[3])
        assert DRT.default_type == default.ruletype
        assert "infoflow4" == default.tclass
        assert DV.target == added_default
        assert DV.source == removed_default
        assert added_range is None
        assert removed_range is None

    #
    # constrains
    #
    def test_added_constrains(self, analysis: setools.PolicyDifference) -> None:
        """Diff: added constrains."""
        lst = sorted(analysis.added_constrains)
        assert 2 == len(lst)

        constrain = lst[0]
        assert CRT.constrain == constrain.ruletype
        assert "infoflow3" == constrain.tclass
        assert set(["null"]) == constrain.perms
        assert ["u1", "u2", "!="] == constrain.expression

        constrain = lst[1]
        assert CRT.constrain == constrain.ruletype
        assert "infoflow5" == constrain.tclass
        assert set(["hi_r"]) == constrain.perms
        assert ['u1', 'u2', '==', 'r1', 'r2', '==', 'and', 't1', set(["system"]), '!=', 'or'] \
            == constrain.expression

    def test_removed_constrains(self, analysis: setools.PolicyDifference) -> None:
        """Diff: removed constrains."""
        lst = sorted(analysis.removed_constrains)
        assert 2 == len(lst)

        constrain = lst[0]
        assert CRT.constrain == constrain.ruletype
        assert "infoflow4" == constrain.tclass
        assert set(["hi_w"]) == constrain.perms
        assert ["u1", "u2", "!="] == constrain.expression

        constrain = lst[1]
        assert CRT.constrain == constrain.ruletype
        assert "infoflow5" == constrain.tclass
        assert set(["hi_r"]) == constrain.perms
        assert ['u1', 'u2', '==', 'r1', 'r2', '==', 'and', 't1', set(["system"]), '==', 'or'] == \
            constrain.expression

    #
    # mlsconstrains
    #
    def test_added_mlsconstrains(self, analysis: setools.PolicyDifference) -> None:
        """Diff: added mlsconstrains."""
        lst = sorted(analysis.added_mlsconstrains)
        assert 2 == len(lst)

        mlsconstrain = lst[0]
        assert CRT.mlsconstrain == mlsconstrain.ruletype
        assert "infoflow3" == mlsconstrain.tclass
        assert set(["null"]) == mlsconstrain.perms
        assert ['l1', 'l2', 'domby', 'h1', 'h2', 'domby', 'and',
                't1', set(["mls_exempt"]), '!=', 'or'] == mlsconstrain.expression

        mlsconstrain = lst[1]
        assert CRT.mlsconstrain == mlsconstrain.ruletype
        assert "infoflow5" == mlsconstrain.tclass
        assert set(["hi_r"]) == mlsconstrain.perms
        assert ['l1', 'l2', 'domby', 'h1', 'h2', 'incomp',
                'and', 't1', set(["mls_exempt"]), '==', 'or'] == mlsconstrain.expression

    def test_removed_mlsconstrains(self, analysis: setools.PolicyDifference) -> None:
        """Diff: removed mlsconstrains."""
        lst = sorted(analysis.removed_mlsconstrains)
        assert 2 == len(lst)

        mlsconstrain = lst[0]
        assert CRT.mlsconstrain == mlsconstrain.ruletype
        assert "infoflow4" == mlsconstrain.tclass
        assert set(["hi_w"]) == mlsconstrain.perms
        assert ['l1', 'l2', 'domby', 'h1', 'h2', 'domby', 'and',
                't1', set(["mls_exempt"]), '==', 'or'] == mlsconstrain.expression

        mlsconstrain = lst[1]
        assert CRT.mlsconstrain == mlsconstrain.ruletype
        assert "infoflow5" == mlsconstrain.tclass
        assert set(["hi_r"]) == mlsconstrain.perms
        assert ['l1', 'l2', 'domby', 'h1', 'h2', 'dom', 'and', 't1', set(["mls_exempt"]), '==',
                'or'] == mlsconstrain.expression

    #
    # validatetrans
    #
    def test_added_validatetrans(self, analysis: setools.PolicyDifference) -> None:
        """Diff: added validatetrans."""
        lst = sorted(analysis.added_validatetrans)
        assert 2 == len(lst)

        validatetrans = lst[0]
        assert CRT.validatetrans == validatetrans.ruletype
        assert "infoflow3" == validatetrans.tclass
        assert ['t1', 't2', '==', 't3', set(["system"]), '==', 'or'] == validatetrans.expression

        validatetrans = lst[1]
        assert CRT.validatetrans == validatetrans.ruletype
        assert "infoflow5" == validatetrans.tclass
        assert ['u1', 'u2', '!=', 'r1', 'r2', '==', 'and', 't3', set(["system"]), '==', 'or'] \
            == validatetrans.expression

    def test_removed_validatetrans(self, analysis: setools.PolicyDifference) -> None:
        """Diff: removed validatetrans."""
        lst = sorted(analysis.removed_validatetrans)
        assert 2 == len(lst)

        validatetrans = lst[0]
        assert CRT.validatetrans == validatetrans.ruletype
        assert "infoflow4" == validatetrans.tclass
        assert ['u1', 'u2', '==', 't3', set(["system"]), '==', 'or'] == validatetrans.expression

        validatetrans = lst[1]
        assert CRT.validatetrans == validatetrans.ruletype
        assert "infoflow5" == validatetrans.tclass
        assert ['u1', 'u2', '==', 'r1', 'r2', '!=', 'and', 't3', set(["system"]), '==', 'or'] \
            == validatetrans.expression

    #
    # mlsvalidatetrans
    #
    def test_added_mlsvalidatetrans(self, analysis: setools.PolicyDifference) -> None:
        """Diff: added mlsvalidatetrans."""
        lst = sorted(analysis.added_mlsvalidatetrans)
        assert 2 == len(lst)

        mlsvalidatetrans = lst[0]
        assert CRT.mlsvalidatetrans == mlsvalidatetrans.ruletype
        assert "infoflow3" == mlsvalidatetrans.tclass
        assert ['l1', 'l2', '==', 'h1', 'h2', '==', 'and', 't3', set(["mls_exempt"]), '==',
                'or'] == mlsvalidatetrans.expression

        mlsvalidatetrans = lst[1]
        assert CRT.mlsvalidatetrans == mlsvalidatetrans.ruletype
        assert "infoflow5" == mlsvalidatetrans.tclass
        assert ['l1', 'l2', 'incomp', 'h1', 'h2', 'domby', 'and', 't3', set(["mls_exempt"]), '==',
                'or'] == mlsvalidatetrans.expression

    def test_removed_mlsvalidatetrans(self, analysis: setools.PolicyDifference) -> None:
        """Diff: removed mlsvalidatetrans."""
        lst = sorted(analysis.removed_mlsvalidatetrans)
        assert 2 == len(lst)

        mlsvalidatetrans = lst[0]
        assert CRT.mlsvalidatetrans == mlsvalidatetrans.ruletype
        assert "infoflow4" == mlsvalidatetrans.tclass
        assert ['l1', 'l2', '==', 'h1', 'h2', '==', 'and', 't3', set(["mls_exempt"]), '==',
                'or'] == mlsvalidatetrans.expression

        mlsvalidatetrans = lst[1]
        assert CRT.mlsvalidatetrans == mlsvalidatetrans.ruletype
        assert "infoflow5" == mlsvalidatetrans.tclass
        assert ['l1', 'l2', 'dom', 'h1', 'h2', 'dom', 'and', 't3', set(["mls_exempt"]), '==',
                'or'] == mlsvalidatetrans.expression

    #
    # typebounds
    #
    def test_added_typebounds(self, analysis: setools.PolicyDifference) -> None:
        """Diff: added typebounds."""
        lst = sorted(analysis.added_typebounds)
        assert 1 == len(lst)

        bounds = lst[0]
        assert BRT.typebounds == bounds.ruletype
        assert "added_parent" == bounds.parent
        assert "added_child" == bounds.child

    def test_removed_typebounds(self, analysis: setools.PolicyDifference) -> None:
        """Diff: removed typebounds."""
        lst = sorted(analysis.removed_typebounds)
        assert 1 == len(lst)

        bounds = lst[0]
        assert BRT.typebounds == bounds.ruletype
        assert "removed_parent" == bounds.parent
        assert "removed_child" == bounds.child

    def test_modified_typebounds(self, analysis: setools.PolicyDifference) -> None:
        """Diff: modified typebounds."""
        lst = sorted(analysis.modified_typebounds, key=lambda x: x.rule)
        assert 1 == len(lst)

        bounds, added_bound, removed_bound = astuple(lst[0])
        assert BRT.typebounds == bounds.ruletype
        assert "mod_child" == bounds.child
        assert "mod_parent_added" == added_bound
        assert "mod_parent_removed" == removed_bound

    #
    # Allowxperm rules
    #
    def test_added_allowxperm_rules(self, analysis: setools.PolicyDifference) -> None:
        """Diff: added allowxperm rules."""
        rules = sorted(analysis.added_allowxperms)
        assert 2 == len(rules)

        # added rule with new type
        util.validate_rule(rules[0], TRT.allowxperm, "added_type", "added_type",
                           tclass="infoflow7", perms=setools.IoctlSet([0x0009]), xperm="ioctl")

        # added rule with existing types
        util.validate_rule(rules[1], TRT.allowxperm, "ax_added_rule_source",
                           "ax_added_rule_target", tclass="infoflow",
                           perms=setools.IoctlSet([0x0002]), xperm="ioctl")

    def test_removed_allowxperm_rules(self, analysis: setools.PolicyDifference) -> None:
        """Diff: removed allowxperm rules."""
        rules = sorted(analysis.removed_allowxperms)
        assert 2 == len(rules)

        # removed rule with existing types
        util.validate_rule(rules[0], TRT.allowxperm, "ax_removed_rule_source",
                           "ax_removed_rule_target", tclass="infoflow",
                           perms=setools.IoctlSet([0x0002]), xperm="ioctl")

        # removed rule with new type
        util.validate_rule(rules[1], TRT.allowxperm, "removed_type", "removed_type",
                           tclass="infoflow7", perms=setools.IoctlSet([0x0009]), xperm="ioctl")

    def test_modified_allowxperm_rules(self, analysis: setools.PolicyDifference) -> None:
        """Diff: modified allowxperm rules."""
        lst = sorted(analysis.modified_allowxperms, key=lambda x: x.rule)
        assert 3 == len(lst)

        # add permissions
        rule, added_perms, removed_perms, matched_perms = astuple(lst[0])
        assert TRT.allowxperm == rule.ruletype
        assert "ax_modified_rule_add_perms" == rule.source
        assert "ax_modified_rule_add_perms" == rule.target
        assert "infoflow" == rule.tclass
        assert setools.IoctlSet([0x000f]) == added_perms
        assert not removed_perms
        assert setools.IoctlSet([0x0004]) == matched_perms

        # add and remove permissions
        rule, added_perms, removed_perms, matched_perms = astuple(lst[1])
        assert TRT.allowxperm == rule.ruletype
        assert "ax_modified_rule_add_remove_perms" == rule.source
        assert "ax_modified_rule_add_remove_perms" == rule.target
        assert "infoflow2" == rule.tclass
        assert setools.IoctlSet([0x0006]) == added_perms
        assert setools.IoctlSet([0x0007]) == removed_perms
        assert setools.IoctlSet([0x0008]) == matched_perms

        # remove permissions
        rule, added_perms, removed_perms, matched_perms = astuple(lst[2])
        assert TRT.allowxperm == rule.ruletype
        assert "ax_modified_rule_remove_perms" == rule.source
        assert "ax_modified_rule_remove_perms" == rule.target
        assert "infoflow" == rule.tclass
        assert not added_perms
        assert setools.IoctlSet([0x0006]) == removed_perms
        assert setools.IoctlSet([0x0005]) == matched_perms

    #
    # Auditallowxperm rules
    #
    def test_added_auditallowxperm_rules(self, analysis: setools.PolicyDifference) -> None:
        """Diff: added auditallowxperm rules."""
        rules = sorted(analysis.added_auditallowxperms)
        assert 2 == len(rules)

        # added rule with existing types
        util.validate_rule(rules[0], TRT.auditallowxperm, "aax_added_rule_source",
                           "aax_added_rule_target", tclass="infoflow",
                           perms=setools.IoctlSet([0x0002]), xperm="ioctl")

        # added rule with new type
        util.validate_rule(rules[1], TRT.auditallowxperm, "added_type", "added_type",
                           tclass="infoflow7", perms=setools.IoctlSet([0x0009]), xperm="ioctl")

    def test_removed_auditallowxperm_rules(self, analysis: setools.PolicyDifference) -> None:
        """Diff: removed auditallowxperm rules."""
        rules = sorted(analysis.removed_auditallowxperms)
        assert 2 == len(rules)

        # removed rule with existing types
        util.validate_rule(rules[0], TRT.auditallowxperm, "aax_removed_rule_source",
                           "aax_removed_rule_target", tclass="infoflow",
                           perms=setools.IoctlSet([0x0002]), xperm="ioctl")

        # removed rule with new type
        util.validate_rule(rules[1], TRT.auditallowxperm, "removed_type", "removed_type",
                           tclass="infoflow7", perms=setools.IoctlSet([0x0009]), xperm="ioctl")

    def test_modified_auditallowxperm_rules(self, analysis: setools.PolicyDifference) -> None:
        """Diff: modified auditallowxperm rules."""
        lst = sorted(analysis.modified_auditallowxperms, key=lambda x: x.rule)
        assert 3 == len(lst)

        # add permissions
        rule, added_perms, removed_perms, matched_perms = astuple(lst[0])
        assert TRT.auditallowxperm == rule.ruletype
        assert "aax_modified_rule_add_perms" == rule.source
        assert "aax_modified_rule_add_perms" == rule.target
        assert "infoflow" == rule.tclass
        assert setools.IoctlSet([0x000f]) == added_perms
        assert not removed_perms
        assert setools.IoctlSet([0x0004]) == matched_perms

        # add and remove permissions
        rule, added_perms, removed_perms, matched_perms = astuple(lst[1])
        assert TRT.auditallowxperm == rule.ruletype
        assert "aax_modified_rule_add_remove_perms" == rule.source
        assert "aax_modified_rule_add_remove_perms" == rule.target
        assert "infoflow2" == rule.tclass
        assert setools.IoctlSet([0x0006]) == added_perms
        assert setools.IoctlSet([0x0007]) == removed_perms
        assert setools.IoctlSet([0x0008]) == matched_perms

        # remove permissions
        rule, added_perms, removed_perms, matched_perms = astuple(lst[2])
        assert TRT.auditallowxperm == rule.ruletype
        assert "aax_modified_rule_remove_perms" == rule.source
        assert "aax_modified_rule_remove_perms" == rule.target
        assert "infoflow" == rule.tclass
        assert not added_perms
        assert setools.IoctlSet([0x0006]) == removed_perms
        assert setools.IoctlSet([0x0005]) == matched_perms

    #
    # Neverallowxperm rules
    #
    def test_added_neverallowxperm_rules(self, analysis: setools.PolicyDifference) -> None:
        """Diff: added neverallowxperm rules."""
        assert not analysis.added_neverallowxperms
        # changed after dropping source policy support
        # rules = sorted(analysis.added_neverallowxperms)
        # assert 2 == len(rules)
        #
        # # added rule with new type
        # util.validate_rule(rules[0], TRT.neverallowxperm, "added_type", "added_type",
        #                    "infoflow7", setools.IoctlSet([0x0009]), xperm="ioctl")
        #
        # # added rule with existing types
        # util.validate_rule(rules[1], TRT.neverallowxperm, "nax_added_rule_source",
        #                    "nax_added_rule_target", "infoflow", setools.IoctlSet([0x0002]),
        #                    xperm="ioctl")

    def test_removed_neverallowxperm_rules(self, analysis: setools.PolicyDifference) -> None:
        """Diff: removed neverallowxperm rules."""
        assert not analysis.removed_neverallowxperms
        # changed after dropping source policy support
        # rules = sorted(analysis.removed_neverallowxperms)
        # assert 2 == len(rules)
        #
        # # removed rule with existing types
        # util.validate_rule(rules[0], TRT.neverallowxperm, "nax_removed_rule_source",
        #                    "nax_removed_rule_target", "infoflow", setools.IoctlSet([0x0002]),
        #                    xperm="ioctl")
        #
        # # removed rule with new type
        # util.validate_rule(rules[1], TRT.neverallowxperm, "removed_type", "removed_type",
        #                    "infoflow7", setools.IoctlSet([0x0009]), xperm="ioctl")

    def test_modified_neverallowxperm_rules(self, analysis: setools.PolicyDifference) -> None:
        """Diff: modified neverallowxperm rules."""
        assert not analysis.modified_neverallowxperms
        # changed after dropping source policy support
        # l = sorted(analysis.modified_neverallowxperms, key=lambda x: x.rule)
        # assert 3 == len(l)
        #
        # # add permissions
        # rule, added_perms, removed_perms, matched_perms = l[0]
        # assert TRT.neverallowxperm == rule.ruletype
        # assert "nax_modified_rule_add_perms" == rule.source
        # assert "nax_modified_rule_add_perms" == rule.target
        # assert "infoflow" == rule.tclass
        # assert setools.IoctlSet([0x000f]) == added_perms
        # assert not removed_perms
        # assert setools.IoctlSet([0x0004]) == matched_perms
        #
        # # add and remove permissions
        # rule, added_perms, removed_perms, matched_perms = l[1]
        # assert TRT.neverallowxperm == rule.ruletype
        # assert "nax_modified_rule_add_remove_perms" == rule.source
        # assert "nax_modified_rule_add_remove_perms" == rule.target
        # assert "infoflow2" == rule.tclass
        # assert setools.IoctlSet([0x0006]) == added_perms
        # assert setools.IoctlSet([0x0007]) == removed_perms
        # assert setools.IoctlSet([0x0008]) == matched_perms
        #
        # # remove permissions
        # rule, added_perms, removed_perms, matched_perms = l[2]
        # assert TRT.neverallowxperm == rule.ruletype
        # assert "nax_modified_rule_remove_perms" == rule.source
        # assert "nax_modified_rule_remove_perms" == rule.target
        # assert "infoflow" == rule.tclass
        # assert not added_perms
        # assert setools.IoctlSet([0x0006]) == removed_perms
        # assert setools.IoctlSet([0x0005]) == matched_perms

    #
    # Dontauditxperm rules
    #
    def test_added_dontauditxperm_rules(self, analysis: setools.PolicyDifference) -> None:
        """Diff: added dontauditxperm rules."""
        rules = sorted(analysis.added_dontauditxperms)
        assert 2 == len(rules)

        # added rule with new type
        util.validate_rule(rules[0], TRT.dontauditxperm, "added_type", "added_type",
                           tclass="infoflow7", perms=setools.IoctlSet([0x0009]), xperm="ioctl")

        # added rule with existing types
        util.validate_rule(rules[1], TRT.dontauditxperm, "dax_added_rule_source",
                           "dax_added_rule_target", tclass="infoflow",
                           perms=setools.IoctlSet([0x0002]), xperm="ioctl")

    def test_removed_dontauditxperm_rules(self, analysis: setools.PolicyDifference) -> None:
        """Diff: removed dontauditxperm rules."""
        rules = sorted(analysis.removed_dontauditxperms)
        assert 2 == len(rules)

        # removed rule with existing types
        util.validate_rule(rules[0], TRT.dontauditxperm, "dax_removed_rule_source",
                           "dax_removed_rule_target", tclass="infoflow",
                           perms=setools.IoctlSet([0x0002]), xperm="ioctl")

        # removed rule with new type
        util.validate_rule(rules[1], TRT.dontauditxperm, "removed_type", "removed_type",
                           tclass="infoflow7", perms=setools.IoctlSet([0x0009]), xperm="ioctl")

    def test_modified_dontauditxperm_rules(self, analysis: setools.PolicyDifference) -> None:
        """Diff: modified dontauditxperm rules."""
        lst = sorted(analysis.modified_dontauditxperms, key=lambda x: x.rule)
        assert 3 == len(lst)

        # add permissions
        rule, added_perms, removed_perms, matched_perms = astuple(lst[0])
        assert TRT.dontauditxperm == rule.ruletype
        assert "dax_modified_rule_add_perms" == rule.source
        assert "dax_modified_rule_add_perms" == rule.target
        assert "infoflow" == rule.tclass
        assert setools.IoctlSet([0x000f]) == added_perms
        assert not removed_perms
        assert setools.IoctlSet([0x0004]) == matched_perms

        # add and remove permissions
        rule, added_perms, removed_perms, matched_perms = astuple(lst[1])
        assert TRT.dontauditxperm == rule.ruletype
        assert "dax_modified_rule_add_remove_perms" == rule.source
        assert "dax_modified_rule_add_remove_perms" == rule.target
        assert "infoflow2" == rule.tclass
        assert setools.IoctlSet([0x0006]) == added_perms
        assert setools.IoctlSet([0x0007]) == removed_perms
        assert setools.IoctlSet([0x0008]) == matched_perms

        # remove permissions
        rule, added_perms, removed_perms, matched_perms = astuple(lst[2])
        assert TRT.dontauditxperm == rule.ruletype
        assert "dax_modified_rule_remove_perms" == rule.source
        assert "dax_modified_rule_remove_perms" == rule.target
        assert "infoflow" == rule.tclass
        assert not added_perms
        assert setools.IoctlSet([0x0006]) == removed_perms
        assert setools.IoctlSet([0x0005]) == matched_perms

    #
    # Ibendportcon statements
    #
    def test_added_ibendportcons(self, analysis: setools.PolicyDifference) -> None:
        """Diff: added ibendportcon statements."""
        rules = sorted(analysis.added_ibendportcons)
        assert 1 == len(rules)
        assert "add" == rules[0].name
        assert 23 == rules[0].port
        assert "system:system:system:s0" == rules[0].context

    def test_removed_ibendportcons(self, analysis: setools.PolicyDifference) -> None:
        """Diff: removed ibendportcon statements."""
        rules = sorted(analysis.removed_ibendportcons)
        assert 1 == len(rules)
        assert "removed" == rules[0].name
        assert 7 == rules[0].port
        assert "system:system:system:s0" == rules[0].context

    def test_modified_ibendportcons(self, analysis: setools.PolicyDifference) -> None:
        """Diff: modified ibendportcon statements"""
        rules = sorted(analysis.modified_ibendportcons)
        assert 1 == len(rules)

        rule, added, removed = astuple(rules[0])
        assert "modified" == rule.name
        assert 13 == rule.port
        assert "modified_change_level:object_r:system:s2" == added
        assert "modified_change_level:object_r:system:s2:c0.c1" == removed

    #
    # Ibpkeycon statements
    #
    def test_added_ibpkeycons(self, analysis: setools.PolicyDifference) -> None:
        """Diff: added ibpkeycon statements."""
        rules = sorted(analysis.added_ibpkeycons)
        assert 2 == len(rules)

        rule = rules[0]
        assert IPv6Address("beef::") == rule.subnet_prefix
        assert 0xe == rule.pkeys.low
        assert 0xe == rule.pkeys.high
        assert "system:system:system:s0" == rule.context

        rule = rules[1]
        assert IPv6Address("dead::") == rule.subnet_prefix
        assert 0xbeef == rule.pkeys.low
        assert 0xdead == rule.pkeys.high
        assert "system:system:system:s0" == rule.context

    def test_removed_ibpkeycons(self, analysis: setools.PolicyDifference) -> None:
        """Diff: removed ibpkeycon statements."""
        rules = sorted(analysis.removed_ibpkeycons)
        assert 2 == len(rules)

        rule = rules[0]
        assert IPv6Address("dccc::") == rule.subnet_prefix
        assert 0xc == rule.pkeys.low
        assert 0xc == rule.pkeys.high
        assert "system:system:system:s0" == rule.context

        rule = rules[1]
        assert IPv6Address("feee::") == rule.subnet_prefix
        assert 0xaaaa == rule.pkeys.low
        assert 0xbbbb == rule.pkeys.high
        assert "system:system:system:s0" == rule.context

    def test_modified_ibpkeycons(self, analysis: setools.PolicyDifference) -> None:
        """Diff: modified ibpkeycon statements"""
        rules = sorted(analysis.modified_ibpkeycons)
        assert 2 == len(rules)

        rule, added, removed = astuple(rules[0])
        assert IPv6Address("aaaa::") == rule.subnet_prefix
        assert 0xcccc == rule.pkeys.low
        assert 0xdddd == rule.pkeys.high
        assert "modified_change_level:object_r:system:s2:c0" == added
        assert "modified_change_level:object_r:system:s2:c1" == removed

        rule, added, removed = astuple(rules[1])
        assert IPv6Address("bbbb::") == rule.subnet_prefix
        assert 0xf == rule.pkeys.low
        assert 0xf == rule.pkeys.high
        assert "modified_change_level:object_r:system:s2:c1" == added
        assert "modified_change_level:object_r:system:s2:c0.c1" == removed


@pytest.mark.obj_args("tests/library/diff_left.conf", "tests/library/diff_right_rmisid.conf")
class TestPolicyDifferenceRmIsid:

    """
    Policy difference test for removed initial SID.

    Since initial SID names are fixed (they don't exist in the binary policy)
    this cannot be in the above test suite.
    """

    def test_removed_initialsids(self, analysis: setools.PolicyDifference) -> None:
        """Diff: removed initialsids."""
        assert set(["file"]) == analysis.removed_initialsids


@pytest.mark.obj_args("tests/library/diff_left.conf", "tests/library/diff_left.conf")
class TestPolicyDifferenceTestNoDiff:

    """Policy difference test with no policy differences."""

    def test_added_types(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no added types"""
        assert not analysis.added_types

    def test_removed_types(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no removed types"""
        assert not analysis.removed_types

    def test_modified_types(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no modified types"""
        assert not analysis.modified_types

    def test_added_roles(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no added roles."""
        assert not analysis.added_roles

    def test_removed_roles(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no removed roles."""
        assert not analysis.removed_roles

    def test_modified_roles(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no modified roles."""
        assert not analysis.modified_roles

    def test_added_commons(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no added commons."""
        assert not analysis.added_commons

    def test_removed_commons(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no removed commons."""
        assert not analysis.removed_commons

    def test_modified_commons(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no modified commons."""
        assert not analysis.modified_commons

    def test_added_classes(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no added classes."""
        assert not analysis.added_classes

    def test_removed_classes(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no removed classes."""
        assert not analysis.removed_classes

    def test_modified_classes(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no modified classes."""
        assert not analysis.modified_classes

    def test_added_allows(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no added allow rules."""
        assert not analysis.added_allows

    def test_removed_allows(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no removed allow rules."""
        assert not analysis.removed_allows

    def test_modified_allows(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no modified allow rules."""
        assert not analysis.modified_allows

    def test_added_auditallows(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no added auditallow rules."""
        assert not analysis.added_auditallows

    def test_removed_auditallows(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no removed auditallow rules."""
        assert not analysis.removed_auditallows

    def test_modified_auditallows(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no modified auditallow rules."""
        assert not analysis.modified_auditallows

    def test_added_neverallows(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no added neverallow rules."""
        assert not analysis.added_neverallows

    def test_removed_neverallows(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no removed neverallow rules."""
        assert not analysis.removed_neverallows

    def test_modified_neverallows(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no modified neverallow rules."""
        assert not analysis.modified_neverallows

    def test_added_dontaudits(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no added dontaudit rules."""
        assert not analysis.added_dontaudits

    def test_removed_dontaudits(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no removed dontaudit rules."""
        assert not analysis.removed_dontaudits

    def test_modified_dontaudits(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no modified dontaudit rules."""
        assert not analysis.modified_dontaudits

    def test_added_type_transitions(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no added type_transition rules."""
        assert not analysis.added_type_transitions

    def test_removed_type_transitions(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no removed type_transition rules."""
        assert not analysis.removed_type_transitions

    def test_modified_type_transitions(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no modified type_transition rules."""
        assert not analysis.modified_type_transitions

    def test_added_type_changes(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no added type_change rules."""
        assert not analysis.added_type_changes

    def test_removed_type_changes(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no removed type_change rules."""
        assert not analysis.removed_type_changes

    def test_modified_type_changes(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no modified type_change rules."""
        assert not analysis.modified_type_changes

    def test_added_type_members(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no added type_member rules."""
        assert not analysis.added_type_members

    def test_removed_type_members(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no removed type_member rules."""
        assert not analysis.removed_type_members

    def test_modified_type_members(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no modified type_member rules."""
        assert not analysis.modified_type_members

    def test_added_range_transitions(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no added range_transition rules."""
        assert not analysis.added_range_transitions

    def test_removed_range_transitions(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no removed range_transition rules."""
        assert not analysis.removed_range_transitions

    def test_modified_range_transitions(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no modified range_transition rules."""
        assert not analysis.modified_range_transitions

    def test_added_role_allows(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no added role_allow rules."""
        assert not analysis.added_role_allows

    def test_removed_role_allows(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no removed role_allow rules."""
        assert not analysis.removed_role_allows

    def test_added_role_transitions(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no added role_transition rules."""
        assert not analysis.added_role_transitions

    def test_removed_role_transitions(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no removed role_transition rules."""
        assert not analysis.removed_role_transitions

    def test_modified_role_transitions(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no modified role_transition rules."""
        assert not analysis.modified_role_transitions

    def test_added_users(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no added users."""
        assert not analysis.added_users

    def test_removed_users(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no removed users."""
        assert not analysis.removed_users

    def test_modified_users(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no modified user rules."""
        assert not analysis.modified_users

    def test_added_type_attributes(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no added type attribute."""
        assert not analysis.added_type_attributes

    def test_removed_type_attributes(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no removed type attributes."""
        assert not analysis.removed_type_attributes

    def test_modified_type_attributes(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no modified type attributes."""
        assert not analysis.modified_type_attributes

    def test_added_booleans(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no added booleans."""
        assert not analysis.added_booleans

    def test_removed_booleans(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no removed booleans."""
        assert not analysis.removed_booleans

    def test_modified_booleans(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no modified booleans."""
        assert not analysis.modified_booleans

    def test_added_categories(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no added categories."""
        assert not analysis.added_categories

    def test_removed_categories(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no removed categories."""
        assert not analysis.removed_categories

    def test_modified_categories(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no modified categories."""
        assert not analysis.modified_categories

    def test_added_sensitivities(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no added sensitivities."""
        assert not analysis.added_sensitivities

    def test_removed_sensitivities(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no removed sensitivities."""
        assert not analysis.removed_sensitivities

    def test_modified_sensitivities(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no modified sensitivities."""
        assert not analysis.modified_sensitivities

    def test_added_initialsids(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no added initialsids."""
        assert not analysis.added_initialsids

    def test_removed_initialsids(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no removed initialsids."""
        assert not analysis.removed_initialsids

    def test_modified_initialsids(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no modified initialsids."""
        assert not analysis.modified_initialsids

    def test_added_fs_uses(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no added fs_uses."""
        assert not analysis.added_fs_uses

    def test_removed_fs_uses(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no removed fs_uses."""
        assert not analysis.removed_fs_uses

    def test_modified_fs_uses(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no modified fs_uses."""
        assert not analysis.modified_fs_uses

    def test_added_genfscons(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no added genfscons."""
        assert not analysis.added_genfscons

    def test_removed_genfscons(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no removed genfscons."""
        assert not analysis.removed_genfscons

    def test_modified_genfscons(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no modified genfscons."""
        assert not analysis.modified_genfscons

    def test_added_levels(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no added levels."""
        assert not analysis.added_levels

    def test_removed_levels(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no removed levels."""
        assert not analysis.removed_levels

    def test_modified_levels(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no modified levels."""
        assert not analysis.modified_levels

    def test_added_netifcons(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no added netifcons."""
        assert not analysis.added_netifcons

    def test_removed_netifcons(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no removed netifcons."""
        assert not analysis.removed_netifcons

    def test_modified_netifcons(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no modified netifcons."""
        assert not analysis.modified_netifcons

    def test_added_nodecons(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no added nodecons."""
        assert not analysis.added_nodecons

    def test_removed_nodecons(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no removed nodecons."""
        assert not analysis.removed_nodecons

    def test_modified_nodecons(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no modified nodecons."""
        assert not analysis.modified_nodecons

    def test_added_polcaps(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no added polcaps."""
        assert not analysis.added_polcaps

    def test_removed_polcaps(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no removed polcaps."""
        assert not analysis.removed_polcaps

    def test_added_portcons(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no added portcons."""
        assert not analysis.added_portcons

    def test_removed_portcons(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no removed portcons."""
        assert not analysis.removed_portcons

    def test_modified_portcons(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no modified portcons."""
        assert not analysis.modified_portcons

    def test_modified_properties(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no modified properties."""
        assert not analysis.modified_properties

    def test_added_defaults(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no added defaults."""
        assert not analysis.added_defaults

    def test_removed_defaults(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no removed defaults."""
        assert not analysis.removed_defaults

    def test_modified_defaults(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no modified defaults."""
        assert not analysis.modified_defaults

    def test_added_constrains(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no added constrains."""
        assert not analysis.added_constrains

    def test_removed_constrains(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no removed constrains."""
        assert not analysis.removed_constrains

    def test_added_mlsconstrains(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no added mlsconstrains."""
        assert not analysis.added_mlsconstrains

    def test_removed_mlsconstrains(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no removed mlsconstrains."""
        assert not analysis.removed_mlsconstrains

    def test_added_validatetrans(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no added validatetrans."""
        assert not analysis.added_validatetrans

    def test_removed_validatetrans(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no removed validatetrans."""
        assert not analysis.removed_validatetrans

    def test_added_mlsvalidatetrans(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no added mlsvalidatetrans."""
        assert not analysis.added_mlsvalidatetrans

    def test_removed_mlsvalidatetrans(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no removed mlsvalidatetrans."""
        assert not analysis.removed_mlsvalidatetrans

    def test_added_typebounds(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no added typebounds."""
        assert not analysis.added_typebounds

    def test_removed_typebounds(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no removed typebounds."""
        assert not analysis.removed_typebounds

    def test_modified_typebounds(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no modified typebounds."""
        assert not analysis.modified_typebounds

    def test_added_allowxperms(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no added allowxperm rules."""
        assert not analysis.added_allowxperms

    def test_removed_allowxperms(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no removed allowxperm rules."""
        assert not analysis.removed_allowxperms

    def test_modified_allowxperms(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no modified allowxperm rules."""
        assert not analysis.modified_allowxperms

    def test_added_auditallowxperms(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no added auditallowxperm rules."""
        assert not analysis.added_auditallowxperms

    def test_removed_auditallowxperms(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no removed auditallowxperm rules."""
        assert not analysis.removed_auditallowxperms

    def test_modified_auditallowxperms(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no modified auditallowxperm rules."""
        assert not analysis.modified_auditallowxperms

    def test_added_neverallowxperms(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no added neverallowxperm rules."""
        assert not analysis.added_neverallowxperms

    def test_removed_neverallowxperms(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no removed neverallowxperm rules."""
        assert not analysis.removed_neverallowxperms

    def test_modified_neverallowxperms(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no modified neverallowxperm rules."""
        assert not analysis.modified_neverallowxperms

    def test_added_dontauditxperms(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no added dontauditxperm rules."""
        assert not analysis.added_dontauditxperms

    def test_removed_dontauditxperms(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no removed dontauditxperm rules."""
        assert not analysis.removed_dontauditxperms

    def test_modified_dontauditxperms(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no modified dontauditxperm rules."""
        assert not analysis.modified_dontauditxperms

    def test_added_ibendportcons(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no added ibendportcon rules."""
        assert not analysis.added_ibendportcons

    def test_removed_ibendportcons(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no removed ibendportcon rules."""
        assert not analysis.removed_ibendportcons

    def test_modified_ibendportcons(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no modified ibendportcon rules."""
        assert not analysis.modified_ibendportcons

    def test_added_ibpkeycons(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no added ibpkeycon rules."""
        assert not analysis.added_ibpkeycons

    def test_removed_ibpkeycons(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no removed ibpkeycon rules."""
        assert not analysis.removed_ibpkeycons

    def test_modified_ibpkeycons(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no modified ibpkeycon rules."""
        assert not analysis.modified_ibpkeycons


@pytest.mark.obj_args("tests/library/diff_left.conf", "tests/library/diff_left_standard.conf",
                      mls_right=False)
class TestPolicyDifferenceTestMLStoStandard:

    """
    Policy difference test between MLS and standard (non-MLS) policy.

    The left policy is an MLS policy.  The right policy is identical to the
    left policy, except with MLS disabled.
    """

    def test_added_types(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no added types"""
        assert not analysis.added_types

    def test_removed_types(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no removed types"""
        assert not analysis.removed_types

    def test_modified_types(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no modified types"""
        assert not analysis.modified_types

    def test_added_roles(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no added roles."""
        assert not analysis.added_roles

    def test_removed_roles(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no removed roles."""
        assert not analysis.removed_roles

    def test_modified_roles(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no modified roles."""
        assert not analysis.modified_roles

    def test_added_commons(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no added commons."""
        assert not analysis.added_commons

    def test_removed_commons(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no removed commons."""
        assert not analysis.removed_commons

    def test_modified_commons(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no modified commons."""
        assert not analysis.modified_commons

    def test_added_classes(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no added classes."""
        assert not analysis.added_classes

    def test_removed_classes(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no removed classes."""
        assert not analysis.removed_classes

    def test_modified_classes(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no modified classes."""
        assert not analysis.modified_classes

    def test_added_allows(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no added allow rules."""
        assert not analysis.added_allows

    def test_removed_allows(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no removed allow rules."""
        assert not analysis.removed_allows

    def test_modified_allows(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no modified allow rules."""
        assert not analysis.modified_allows

    def test_added_auditallows(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no added auditallow rules."""
        assert not analysis.added_auditallows

    def test_removed_auditallows(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no removed auditallow rules."""
        assert not analysis.removed_auditallows

    def test_modified_auditallows(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no modified auditallow rules."""
        assert not analysis.modified_auditallows

    def test_added_neverallows(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no added neverallow rules."""
        assert not analysis.added_neverallows

    def test_removed_neverallows(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no removed neverallow rules."""
        assert not analysis.removed_neverallows

    def test_modified_neverallows(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no modified neverallow rules."""
        assert not analysis.modified_neverallows

    def test_added_dontaudits(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no added dontaudit rules."""
        assert not analysis.added_dontaudits

    def test_removed_dontaudits(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no removed dontaudit rules."""
        assert not analysis.removed_dontaudits

    def test_modified_dontaudits(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no modified dontaudit rules."""
        assert not analysis.modified_dontaudits

    def test_added_type_transitions(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no added type_transition rules."""
        assert not analysis.added_type_transitions

    def test_removed_type_transitions(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no removed type_transition rules."""
        assert not analysis.removed_type_transitions

    def test_modified_type_transitions(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no modified type_transition rules."""
        assert not analysis.modified_type_transitions

    def test_added_type_changes(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no added type_change rules."""
        assert not analysis.added_type_changes

    def test_removed_type_changes(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no removed type_change rules."""
        assert not analysis.removed_type_changes

    def test_modified_type_changes(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no modified type_change rules."""
        assert not analysis.modified_type_changes

    def test_added_type_members(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no added type_member rules."""
        assert not analysis.added_type_members

    def test_removed_type_members(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no removed type_member rules."""
        assert not analysis.removed_type_members

    def test_modified_type_members(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no modified type_member rules."""
        assert not analysis.modified_type_members

    def test_added_range_transitions(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no added range_transition rules."""
        assert not analysis.added_range_transitions

    def test_removed_range_transitions(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: all range_transition rules removed."""
        assert analysis.left_policy.range_transition_count == \
            len(analysis.removed_range_transitions)

    def test_modified_range_transitions(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no modified range_transition rules."""
        assert not analysis.modified_range_transitions

    def test_added_role_allows(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no added role_allow rules."""
        assert not analysis.added_role_allows

    def test_removed_role_allows(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no removed role_allow rules."""
        assert not analysis.removed_role_allows

    def test_added_role_transitions(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no added role_transition rules."""
        assert not analysis.added_role_transitions

    def test_removed_role_transitions(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no removed role_transition rules."""
        assert not analysis.removed_role_transitions

    def test_modified_role_transitions(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no modified role_transition rules."""
        assert not analysis.modified_role_transitions

    def test_added_users(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no added users."""
        assert not analysis.added_users

    def test_removed_users(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no removed users."""
        assert not analysis.removed_users

    def test_modified_users(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: all users modified."""
        assert analysis.left_policy.user_count == len(analysis.modified_users)

    def test_added_type_attributes(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no added type attribute."""
        assert not analysis.added_type_attributes

    def test_removed_type_attributes(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no removed type attributes."""
        assert not analysis.removed_type_attributes

    def test_modified_type_attributes(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no modified type attributes."""
        assert not analysis.modified_type_attributes

    def test_added_booleans(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no added booleans."""
        assert not analysis.added_booleans

    def test_removed_booleans(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no removed booleans."""
        assert not analysis.removed_booleans

    def test_modified_booleans(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no modified booleans."""
        assert not analysis.modified_booleans

    def test_added_categories(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no added categories."""
        assert not analysis.added_categories

    def test_removed_categories(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: all categories removed."""
        assert analysis.left_policy.category_count == len(analysis.removed_categories)

    def test_modified_categories(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no modified categories."""
        assert not analysis.modified_categories

    def test_added_sensitivities(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no added sensitivities."""
        assert not analysis.added_sensitivities

    def test_removed_sensitivities(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: all sensitivities removed."""
        assert analysis.left_policy.level_count == len(analysis.removed_sensitivities)

    def test_modified_sensitivities(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no modified sensitivities."""
        assert not analysis.modified_sensitivities

    def test_added_initialsids(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no added initialsids."""
        assert not analysis.added_initialsids

    def test_removed_initialsids(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no removed initialsids."""
        assert not analysis.removed_initialsids

    def test_modified_initialsids(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: all initialsids modified."""
        assert analysis.left_policy.initialsids_count == len(analysis.modified_initialsids)

    def test_added_fs_uses(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no added fs_uses."""
        assert not analysis.added_fs_uses

    def test_removed_fs_uses(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no removed fs_uses."""
        assert not analysis.removed_fs_uses

    def test_modified_fs_uses(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: all fs_uses modified."""
        assert analysis.left_policy.fs_use_count == len(analysis.modified_fs_uses)

    def test_added_genfscons(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no added genfscons."""
        assert not analysis.added_genfscons

    def test_removed_genfscons(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no removed genfscons."""
        assert not analysis.removed_genfscons

    def test_modified_genfscons(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: all genfscons modified."""
        assert analysis.left_policy.genfscon_count == len(analysis.modified_genfscons)

    def test_added_levels(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no added levels."""
        assert not analysis.added_levels

    def test_removed_levels(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: all levels removed."""
        assert analysis.left_policy.level_count == len(analysis.removed_levels)

    def test_modified_levels(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no modified levels."""
        assert not analysis.modified_levels

    def test_added_netifcons(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no added netifcons."""
        assert not analysis.added_netifcons

    def test_removed_netifcons(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no removed netifcons."""
        assert not analysis.removed_netifcons

    def test_modified_netifcons(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: all netifcons modified."""
        assert analysis.left_policy.netifcon_count == len(analysis.modified_netifcons)

    def test_added_nodecons(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no added nodecons."""
        assert not analysis.added_nodecons

    def test_removed_nodecons(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no removed nodecons."""
        assert not analysis.removed_nodecons

    def test_modified_nodecons(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: all nodecons modified."""
        assert analysis.left_policy.nodecon_count == len(analysis.modified_nodecons)

    def test_added_polcaps(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no added polcaps."""
        assert not analysis.added_polcaps

    def test_removed_polcaps(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no removed polcaps."""
        assert not analysis.removed_polcaps

    def test_added_portcons(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no added portcons."""
        assert not analysis.added_portcons

    def test_removed_portcons(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no removed portcons."""
        assert not analysis.removed_portcons

    def test_modified_portcons(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: all portcons modified."""
        assert analysis.left_policy.portcon_count == len(analysis.modified_portcons)

    def test_modified_properties(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: MLS property modified only."""
        assert 1 == len(analysis.modified_properties)

        name, added, removed = astuple(analysis.modified_properties[0])
        assert "MLS" == name
        assert added is False
        assert removed is True

    def test_added_defaults(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no added defaults."""
        assert not analysis.added_defaults

    def test_removed_defaults(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: all default_range removed."""
        assert sum(1 for d in analysis.left_policy.defaults() if d.ruletype == DRT.default_range) \
            == len(analysis.removed_defaults)

    def test_modified_defaults(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no defaults modified."""
        assert not analysis.modified_defaults

    def test_added_constraints(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no added constraints."""
        assert not analysis.added_constrains

    def test_removed_constraints(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no removed constraints."""
        assert not analysis.removed_constrains

    def test_added_validatetrans(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no added validatetrans."""
        assert not analysis.added_validatetrans

    def test_removed_validatetrans(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no removed validatetrans."""
        assert not analysis.removed_validatetrans

    def test_added_mlsconstraints(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no added mlsconstraints."""
        assert not analysis.added_mlsconstrains

    def test_removed_mlsconstraints(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: all mlsconstraints removed."""
        assert sum(1 for m in analysis.left_policy.constraints() if
                   m.ruletype == CRT.mlsconstrain) == len(analysis.removed_mlsconstrains)

    def test_added_mlsvalidatetrans(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no added mlsvalidatetrans."""
        assert not analysis.added_mlsvalidatetrans

    def test_removed_mlsvalidatetrans(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: all mlsvalidatetrans removed."""
        assert sum(1 for m in analysis.left_policy.constraints()
                   if m.ruletype == CRT.mlsvalidatetrans) == \
            len(analysis.removed_mlsvalidatetrans)

    def test_added_typebounds(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no added typebounds."""
        assert not analysis.added_typebounds

    def test_removed_typebounds(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no removed typebounds."""
        assert not analysis.removed_typebounds

    def test_modified_typebounds(self, analysis: setools.PolicyDifference) -> None:
        """MLSvsStandardDiff: no modified typebounds."""
        assert not analysis.modified_typebounds

    def test_added_allowxperms(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no added allowxperm rules."""
        assert not analysis.added_allowxperms

    def test_removed_allowxperms(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no removed allowxperm rules."""
        assert not analysis.removed_allowxperms

    def test_modified_allowxperms(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no modified allowxperm rules."""
        assert not analysis.modified_allowxperms

    def test_added_auditallowxperms(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no added auditallowxperm rules."""
        assert not analysis.added_auditallowxperms

    def test_removed_auditallowxperms(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no removed auditallowxperm rules."""
        assert not analysis.removed_auditallowxperms

    def test_modified_auditallowxperms(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no modified auditallowxperm rules."""
        assert not analysis.modified_auditallowxperms

    def test_added_neverallowxperms(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no added neverallowxperm rules."""
        assert not analysis.added_neverallowxperms

    def test_removed_neverallowxperms(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no removed neverallowxperm rules."""
        assert not analysis.removed_neverallowxperms

    def test_modified_neverallowxperms(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no modified neverallowxperm rules."""
        assert not analysis.modified_neverallowxperms

    def test_added_dontauditxperms(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no added dontauditxperm rules."""
        assert not analysis.added_dontauditxperms

    def test_removed_dontauditxperms(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no removed dontauditxperm rules."""
        assert not analysis.removed_dontauditxperms

    def test_modified_dontauditxperms(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no modified dontauditxperm rules."""
        assert not analysis.modified_dontauditxperms

    def test_added_ibpkeycons(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no added ibpkeycon rules."""
        assert not analysis.added_ibpkeycons

    def test_removed_ibpkeycons(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no removed ibpkeycon rules."""
        assert not analysis.removed_ibpkeycons

    def test_modified_ibpkeycons(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no modified ibpkeycon rules."""
        assert analysis.left_policy.ibpkeycon_count == len(analysis.modified_ibpkeycons)

    def test_added_ibendportcons(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no added ibendportcon rules."""
        assert not analysis.added_ibendportcons

    def test_removed_ibendportcons(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no removed ibendportcon rules."""
        assert not analysis.removed_ibendportcons

    def test_modified_ibendportcons(self, analysis: setools.PolicyDifference) -> None:
        """NoDiff: no modified ibendportcon rules."""
        assert analysis.left_policy.ibendportcon_count == len(analysis.modified_ibendportcons)


@pytest.mark.obj_args("tests/library/diff_left.conf", "tests/library/diff_left_redundant.conf")
class TestPolicyDifferenceTestRedundant:

    """
    Policy difference test with redundant rules.
    There should be no policy differences.
    """

    def test_added_allows(self, analysis: setools.PolicyDifference) -> None:
        """Redundant: no added allow rules."""
        assert not analysis.added_allows

    def test_removed_allows(self, analysis: setools.PolicyDifference) -> None:
        """Redundant: no removed allow rules."""
        assert not analysis.removed_allows

    def test_modified_allows(self, analysis: setools.PolicyDifference) -> None:
        """Redundant: no modified allow rules."""
        assert not analysis.modified_allows
