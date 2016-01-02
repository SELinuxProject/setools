# Copyright 2015, Tresys Technology, LLC
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

from setools import SELinuxPolicy, PolicyDifference

from .mixins import ValidateRule


class PolicyDifferenceTest(ValidateRule, unittest.TestCase):

    """Policy difference tests."""

    def setUp(self):
        self.diff = PolicyDifference(SELinuxPolicy("tests/diff_left.conf"),
                                     SELinuxPolicy("tests/diff_right.conf"))

    #
    # Types
    #
    def test_added_types(self):
        """Diff: added type"""
        self.assertSetEqual(set(["added_type"]), self.diff.added_types)

    def test_removed_types(self):
        """Diff: modified type"""
        self.assertSetEqual(set(["removed_type"]), self.diff.removed_types)

    def test_modified_types_count(self):
        """Diff: total modified types"""
        self.assertEqual(6, len(self.diff.modified_types))

    def test_modified_types_remove_attr(self):
        """Diff: modified type with removed attribute."""
        self.assertIn("modified_remove_attr", self.diff.modified_types)
        removed_attrs = self.diff.modified_types["modified_remove_attr"].removed_attributes
        self.assertSetEqual(set(["an_attr"]), removed_attrs)
        self.assertFalse(self.diff.modified_types["modified_remove_attr"].added_attributes)
        self.assertFalse(self.diff.modified_types["modified_remove_attr"].matched_attributes)
        self.assertFalse(self.diff.modified_types["modified_remove_attr"].modified_permissive)
        self.assertFalse(self.diff.modified_types["modified_remove_attr"].permissive)
        self.assertFalse(self.diff.modified_types["modified_remove_attr"].added_aliases)
        self.assertFalse(self.diff.modified_types["modified_remove_attr"].removed_aliases)
        self.assertFalse(self.diff.modified_types["modified_remove_attr"].matched_aliases)

    def test_modified_types_remove_alias(self):
        """Diff: modified type with removed alias."""
        self.assertIn("modified_remove_alias", self.diff.modified_types)
        removed_alias = self.diff.modified_types["modified_remove_alias"].removed_aliases
        self.assertSetEqual(set(["an_alias"]), removed_alias)
        self.assertFalse(self.diff.modified_types["modified_remove_alias"].added_attributes)
        self.assertFalse(self.diff.modified_types["modified_remove_alias"].removed_attributes)
        self.assertFalse(self.diff.modified_types["modified_remove_alias"].matched_attributes)
        self.assertFalse(self.diff.modified_types["modified_remove_alias"].modified_permissive)
        self.assertFalse(self.diff.modified_types["modified_remove_alias"].permissive)
        self.assertFalse(self.diff.modified_types["modified_remove_alias"].added_aliases)
        self.assertFalse(self.diff.modified_types["modified_remove_alias"].matched_aliases)

    def test_modified_types_remove_permissive(self):
        """Diff: modified type with removed permissve."""
        self.assertIn("modified_remove_permissive", self.diff.modified_types)
        self.assertFalse(self.diff.modified_types["modified_remove_permissive"].added_attributes)
        self.assertFalse(self.diff.modified_types["modified_remove_permissive"].removed_attributes)
        self.assertFalse(self.diff.modified_types["modified_remove_permissive"].matched_attributes)
        self.assertTrue(self.diff.modified_types["modified_remove_permissive"].modified_permissive)
        self.assertTrue(self.diff.modified_types["modified_remove_permissive"].permissive)
        self.assertFalse(self.diff.modified_types["modified_remove_permissive"].added_aliases)
        self.assertFalse(self.diff.modified_types["modified_remove_permissive"].removed_aliases)
        self.assertFalse(self.diff.modified_types["modified_remove_permissive"].matched_aliases)

    def test_modified_types_add_attr(self):
        """Diff: modified type with added attribute."""
        self.assertIn("modified_add_attr", self.diff.modified_types)
        added_attrs = self.diff.modified_types["modified_add_attr"].added_attributes
        self.assertSetEqual(set(["an_attr"]), added_attrs)
        self.assertFalse(self.diff.modified_types["modified_add_attr"].removed_attributes)
        self.assertFalse(self.diff.modified_types["modified_add_attr"].matched_attributes)
        self.assertFalse(self.diff.modified_types["modified_add_attr"].modified_permissive)
        self.assertFalse(self.diff.modified_types["modified_add_attr"].permissive)
        self.assertFalse(self.diff.modified_types["modified_add_attr"].added_aliases)
        self.assertFalse(self.diff.modified_types["modified_add_attr"].removed_aliases)
        self.assertFalse(self.diff.modified_types["modified_add_attr"].matched_aliases)

    def test_modified_types_add_alias(self):
        """Diff: modified type with added alias."""
        self.assertIn("modified_add_alias", self.diff.modified_types)
        added_alias = self.diff.modified_types["modified_add_alias"].added_aliases
        self.assertSetEqual(set(["an_alias"]), added_alias)
        self.assertFalse(self.diff.modified_types["modified_add_alias"].added_attributes)
        self.assertFalse(self.diff.modified_types["modified_add_alias"].removed_attributes)
        self.assertFalse(self.diff.modified_types["modified_add_alias"].matched_attributes)
        self.assertFalse(self.diff.modified_types["modified_add_alias"].modified_permissive)
        self.assertFalse(self.diff.modified_types["modified_add_alias"].permissive)
        self.assertFalse(self.diff.modified_types["modified_add_alias"].removed_aliases)
        self.assertFalse(self.diff.modified_types["modified_add_alias"].matched_aliases)

    def test_modified_types_add_permissive(self):
        """Diff: modified type with added permissive."""
        self.assertIn("modified_add_permissive", self.diff.modified_types)
        self.assertFalse(self.diff.modified_types["modified_add_permissive"].added_attributes)
        self.assertFalse(self.diff.modified_types["modified_add_permissive"].removed_attributes)
        self.assertFalse(self.diff.modified_types["modified_add_permissive"].matched_attributes)
        self.assertTrue(self.diff.modified_types["modified_add_permissive"].modified_permissive)
        self.assertFalse(self.diff.modified_types["modified_add_permissive"].permissive)
        self.assertFalse(self.diff.modified_types["modified_add_permissive"].added_aliases)
        self.assertFalse(self.diff.modified_types["modified_add_permissive"].removed_aliases)
        self.assertFalse(self.diff.modified_types["modified_add_permissive"].matched_aliases)

    #
    # Roles
    #
    def test_added_role(self):
        """Diff: added role."""
        self.assertSetEqual(set(["added_role"]), self.diff.added_roles)

    def test_removed_role(self):
        """Diff: removed role."""
        self.assertSetEqual(set(["removed_role"]), self.diff.removed_roles)

    def test_modified_role_count(self):
        """Diff: modified role."""
        self.assertIn("object_r", self.diff.modified_roles)
        self.assertEqual(3, len(self.diff.modified_roles))

    def test_modified_role_add_type(self):
        """Diff: modified role with added type."""
        self.assertSetEqual(set(["system"]),
                            self.diff.modified_roles["modified_add_type"].added_types)
        self.assertFalse(self.diff.modified_roles["modified_add_type"].removed_types)

    def test_modified_role_remove_type(self):
        """Diff: modified role with removed type."""
        self.assertSetEqual(set(["system"]),
                            self.diff.modified_roles["modified_remove_type"].removed_types)
        self.assertFalse(self.diff.modified_roles["modified_remove_type"].added_types)

    #
    # Commons
    #
    def test_added_common(self):
        """Diff: added common."""
        self.assertSetEqual(set(["added_common"]), self.diff.added_commons)

    def test_removed_common(self):
        """Diff: removed common."""
        self.assertSetEqual(set(["removed_common"]), self.diff.removed_commons)

    def test_modified_common_count(self):
        """Diff: modified common count."""
        self.assertEqual(2, len(self.diff.modified_commons))

    def test_modified_common_add_perm(self):
        """Diff: modified common with added perm."""
        self.assertSetEqual(set(["added_perm"]),
                            self.diff.modified_commons["modified_add_perm"].added_perms)
        self.assertFalse(self.diff.modified_commons["modified_add_perm"].removed_perms)

    def test_modified_common_remove_perm(self):
        """Diff: modified common with removed perm."""
        self.assertSetEqual(set(["removed_perm"]),
                            self.diff.modified_commons["modified_remove_perm"].removed_perms)
        self.assertFalse(self.diff.modified_commons["modified_remove_perm"].added_perms)

    #
    # Classes
    #
    def test_added_class(self):
        """Diff: added class."""
        self.assertSetEqual(set(["added_class"]), self.diff.added_classes)

    def test_removed_class(self):
        """Diff: removed class."""
        self.assertSetEqual(set(["removed_class"]), self.diff.removed_classes)

    def test_modified_class_count(self):
        """Diff: modified class count."""
        self.assertEqual(3, len(self.diff.modified_classes))

    def test_modified_class_add_perm(self):
        """Diff: modified class with added perm."""
        self.assertSetEqual(set(["added_perm"]),
                            self.diff.modified_classes["modified_add_perm"].added_perms)
        self.assertFalse(self.diff.modified_classes["modified_add_perm"].removed_perms)

    def test_modified_class_remove_perm(self):
        """Diff: modified class with removed perm."""
        self.assertSetEqual(set(["removed_perm"]),
                            self.diff.modified_classes["modified_remove_perm"].removed_perms)
        self.assertFalse(self.diff.modified_classes["modified_remove_perm"].added_perms)

    def test_modified_class_change_common(self):
        """Diff: modified class due to modified common."""
        self.assertSetEqual(set(["old_com"]),
                            self.diff.modified_classes["modified_change_common"].removed_perms)
        self.assertSetEqual(set(["new_com"]),
                            self.diff.modified_classes["modified_change_common"].added_perms)

    #
    # Allow rules
    #
    def test_added_allow_rules(self):
        """Diff: added allow rules."""
        rules = sorted(self.diff.added_allows)
        self.assertEqual(5, len(rules))

        # added rule with existing types
        self.validate_rule(rules[0], "allow", "added_rule_source", "added_rule_target", "infoflow",
                           set(["med_w"]))

        # added rule with new type
        self.validate_rule(rules[1], "allow", "added_type", "added_type", "infoflow2",
                           set(["med_w"]))

        # rule moved out of a conditional
        self.validate_rule(rules[2], "allow", "move_from_bool", "move_from_bool", "infoflow4",
                           set(["hi_r"]))

        # rule moved into a conditional
        self.validate_rule(rules[3], "allow", "move_to_bool", "move_to_bool", "infoflow4",
                           set(["hi_w"]), cond="move_to_bool_b", cond_block=True)

        # rule moved from one conditional block to another (true to false)
        self.validate_rule(rules[4], "allow", "system", "switch_block", "infoflow6",
                           set(["hi_r"]), cond="switch_block_b", cond_block=False)

    def test_removed_allow_rules(self):
        """Diff: removed allow rules."""
        rules = sorted(self.diff.removed_allows)
        self.assertEqual(5, len(rules))

        # rule moved out of a conditional
        self.validate_rule(rules[0], "allow", "move_from_bool", "move_from_bool", "infoflow4",
                           set(["hi_r"]), cond="move_from_bool_b", cond_block=True)

        # rule moved into a conditional
        self.validate_rule(rules[1], "allow", "move_to_bool", "move_to_bool", "infoflow4",
                           set(["hi_w"]))

        # removed rule with existing types
        self.validate_rule(rules[2], "allow", "removed_rule_source", "removed_rule_target",
                           "infoflow", set(["hi_r"]))

        # removed rule with new type
        self.validate_rule(rules[3], "allow", "removed_type", "removed_type", "infoflow3",
                           set(["null"]))

        # rule moved from one conditional block to another (true to false)
        self.validate_rule(rules[4], "allow", "system", "switch_block", "infoflow6",
                           set(["hi_r"]), cond="switch_block_b", cond_block=True)

    def test_modified_allow_rules(self):
        """Diff: modified allow rules."""
        l = sorted(self.diff.modified_allows)
        self.assertEqual(3, len(l))

        # add permissions
        rule, added_perms, removed_perms, matched_perms = l[0]
        self.assertEqual("allow", rule.ruletype)
        self.assertEqual("modified_rule_add_perms", rule.source)
        self.assertEqual("modified_rule_add_perms", rule.target)
        self.assertEqual("infoflow", rule.tclass)
        self.assertSetEqual(set(["hi_w"]), added_perms)
        self.assertFalse(removed_perms)
        self.assertSetEqual(set(["hi_r"]), matched_perms)

        # add and remove permissions
        rule, added_perms, removed_perms, matched_perms = l[1]
        self.assertEqual("allow", rule.ruletype)
        self.assertEqual("modified_rule_add_remove_perms", rule.source)
        self.assertEqual("modified_rule_add_remove_perms", rule.target)
        self.assertEqual("infoflow2", rule.tclass)
        self.assertSetEqual(set(["super_r"]), added_perms)
        self.assertSetEqual(set(["super_w"]), removed_perms)
        self.assertSetEqual(set(["low_w"]), matched_perms)

        # remove permissions
        rule, added_perms, removed_perms, matched_perms = l[2]
        self.assertEqual("allow", rule.ruletype)
        self.assertEqual("modified_rule_remove_perms", rule.source)
        self.assertEqual("modified_rule_remove_perms", rule.target)
        self.assertEqual("infoflow", rule.tclass)
        self.assertFalse(added_perms)
        self.assertSetEqual(set(["low_r"]), removed_perms)
        self.assertSetEqual(set(["low_w"]), matched_perms)

    #
    # Auditallow rules
    #
    def test_added_auditallow_rules(self):
        """Diff: added auditallow rules."""
        rules = sorted(self.diff.added_auditallows)
        self.assertEqual(5, len(rules))

        # added rule with existing types
        self.validate_rule(rules[0], "auditallow", "aa_added_rule_source", "aa_added_rule_target",
                           "infoflow", set(["med_w"]))

        # rule moved out of a conditional
        self.validate_rule(rules[1], "auditallow", "aa_move_from_bool", "aa_move_from_bool",
                           "infoflow4", set(["hi_r"]))

        # rule moved into a conditional
        self.validate_rule(rules[2], "auditallow", "aa_move_to_bool", "aa_move_to_bool",
                           "infoflow4", set(["hi_w"]), cond="aa_move_to_bool_b", cond_block=True)

        # added rule with new type
        self.validate_rule(rules[3], "auditallow", "added_type", "added_type", "infoflow7",
                           set(["super_none"]))

        # rule moved from one conditional block to another (true to false)
        self.validate_rule(rules[4], "auditallow", "system", "aa_switch_block", "infoflow6",
                           set(["hi_r"]), cond="aa_switch_block_b", cond_block=False)

    def test_removed_auditallow_rules(self):
        """Diff: removed auditallow rules."""
        rules = sorted(self.diff.removed_auditallows)
        self.assertEqual(5, len(rules))

        # rule moved out of a conditional
        self.validate_rule(rules[0], "auditallow", "aa_move_from_bool", "aa_move_from_bool",
                           "infoflow4", set(["hi_r"]), cond="aa_move_from_bool_b", cond_block=True)

        # rule moved into a conditional
        self.validate_rule(rules[1], "auditallow", "aa_move_to_bool", "aa_move_to_bool",
                           "infoflow4", set(["hi_w"]))

        # removed rule with existing types
        self.validate_rule(rules[2], "auditallow", "aa_removed_rule_source",
                           "aa_removed_rule_target", "infoflow", set(["hi_r"]))

        # removed rule with new type
        self.validate_rule(rules[3], "auditallow", "removed_type", "removed_type", "infoflow7",
                           set(["super_unmapped"]))

        # rule moved from one conditional block to another (true to false)
        self.validate_rule(rules[4], "auditallow", "system", "aa_switch_block", "infoflow6",
                           set(["hi_r"]), cond="aa_switch_block_b", cond_block=True)

    def test_modified_auditallow_rules(self):
        """Diff: modified auditallow rules."""
        l = sorted(self.diff.modified_auditallows)
        self.assertEqual(3, len(l))

        # add permissions
        rule, added_perms, removed_perms, matched_perms = l[0]
        self.assertEqual("auditallow", rule.ruletype)
        self.assertEqual("aa_modified_rule_add_perms", rule.source)
        self.assertEqual("aa_modified_rule_add_perms", rule.target)
        self.assertEqual("infoflow", rule.tclass)
        self.assertSetEqual(set(["hi_w"]), added_perms)
        self.assertFalse(removed_perms)
        self.assertSetEqual(set(["hi_r"]), matched_perms)

        # add and remove permissions
        rule, added_perms, removed_perms, matched_perms = l[1]
        self.assertEqual("auditallow", rule.ruletype)
        self.assertEqual("aa_modified_rule_add_remove_perms", rule.source)
        self.assertEqual("aa_modified_rule_add_remove_perms", rule.target)
        self.assertEqual("infoflow2", rule.tclass)
        self.assertSetEqual(set(["super_r"]), added_perms)
        self.assertSetEqual(set(["super_w"]), removed_perms)
        self.assertSetEqual(set(["low_w"]), matched_perms)

        # remove permissions
        rule, added_perms, removed_perms, matched_perms = l[2]
        self.assertEqual("auditallow", rule.ruletype)
        self.assertEqual("aa_modified_rule_remove_perms", rule.source)
        self.assertEqual("aa_modified_rule_remove_perms", rule.target)
        self.assertEqual("infoflow", rule.tclass)
        self.assertFalse(added_perms)
        self.assertSetEqual(set(["low_r"]), removed_perms)
        self.assertSetEqual(set(["low_w"]), matched_perms)

    #
    # Dontaudit rules
    #
    def test_added_dontaudit_rules(self):
        """Diff: added dontaudit rules."""
        rules = sorted(self.diff.added_dontaudits)
        self.assertEqual(5, len(rules))

        # added rule with new type
        self.validate_rule(rules[0], "dontaudit", "added_type", "added_type", "infoflow7",
                           set(["super_none"]))

        # added rule with existing types
        self.validate_rule(rules[1], "dontaudit", "da_added_rule_source", "da_added_rule_target",
                           "infoflow", set(["med_w"]))

        # rule moved out of a conditional
        self.validate_rule(rules[2], "dontaudit", "da_move_from_bool", "da_move_from_bool",
                           "infoflow4", set(["hi_r"]))

        # rule moved into a conditional
        self.validate_rule(rules[3], "dontaudit", "da_move_to_bool", "da_move_to_bool",
                           "infoflow4", set(["hi_w"]), cond="da_move_to_bool_b", cond_block=True)

        # rule moved from one conditional block to another (true to false)
        self.validate_rule(rules[4], "dontaudit", "system", "da_switch_block", "infoflow6",
                           set(["hi_r"]), cond="da_switch_block_b", cond_block=False)

    def test_removed_dontaudit_rules(self):
        """Diff: removed dontaudit rules."""
        rules = sorted(self.diff.removed_dontaudits)
        self.assertEqual(5, len(rules))

        # rule moved out of a conditional
        self.validate_rule(rules[0], "dontaudit", "da_move_from_bool", "da_move_from_bool",
                           "infoflow4", set(["hi_r"]), cond="da_move_from_bool_b", cond_block=True)

        # rule moved into a conditional
        self.validate_rule(rules[1], "dontaudit", "da_move_to_bool", "da_move_to_bool",
                           "infoflow4", set(["hi_w"]))

        # removed rule with existing types
        self.validate_rule(rules[2], "dontaudit", "da_removed_rule_source",
                           "da_removed_rule_target", "infoflow", set(["hi_r"]))

        # removed rule with new type
        self.validate_rule(rules[3], "dontaudit", "removed_type", "removed_type", "infoflow7",
                           set(["super_both"]))

        # rule moved from one conditional block to another (true to false)
        self.validate_rule(rules[4], "dontaudit", "system", "da_switch_block", "infoflow6",
                           set(["hi_r"]), cond="da_switch_block_b", cond_block=True)

    def test_modified_dontaudit_rules(self):
        """Diff: modified dontaudit rules."""
        l = sorted(self.diff.modified_dontaudits)
        self.assertEqual(3, len(l))

        # add permissions
        rule, added_perms, removed_perms, matched_perms = l[0]
        self.assertEqual("dontaudit", rule.ruletype)
        self.assertEqual("da_modified_rule_add_perms", rule.source)
        self.assertEqual("da_modified_rule_add_perms", rule.target)
        self.assertEqual("infoflow", rule.tclass)
        self.assertSetEqual(set(["hi_w"]), added_perms)
        self.assertFalse(removed_perms)
        self.assertSetEqual(set(["hi_r"]), matched_perms)

        # add and remove permissions
        rule, added_perms, removed_perms, matched_perms = l[1]
        self.assertEqual("dontaudit", rule.ruletype)
        self.assertEqual("da_modified_rule_add_remove_perms", rule.source)
        self.assertEqual("da_modified_rule_add_remove_perms", rule.target)
        self.assertEqual("infoflow2", rule.tclass)
        self.assertSetEqual(set(["super_r"]), added_perms)
        self.assertSetEqual(set(["super_w"]), removed_perms)
        self.assertSetEqual(set(["low_w"]), matched_perms)

        # remove permissions
        rule, added_perms, removed_perms, matched_perms = l[2]
        self.assertEqual("dontaudit", rule.ruletype)
        self.assertEqual("da_modified_rule_remove_perms", rule.source)
        self.assertEqual("da_modified_rule_remove_perms", rule.target)
        self.assertEqual("infoflow", rule.tclass)
        self.assertFalse(added_perms)
        self.assertSetEqual(set(["low_r"]), removed_perms)
        self.assertSetEqual(set(["low_w"]), matched_perms)

    #
    # Neverallow rules
    #
    def test_added_neverallow_rules(self):
        """Diff: added neverallow rules."""
        rules = sorted(self.diff.added_neverallows)
        self.assertEqual(2, len(rules))

        # added rule with new type
        self.validate_rule(rules[0], "neverallow", "added_type", "added_type", "added_class",
                           set(["new_class_perm"]))

        # added rule with existing types
        self.validate_rule(rules[1], "neverallow", "na_added_rule_source", "na_added_rule_target",
                           "infoflow", set(["med_w"]))

    def test_removed_neverallow_rules(self):
        """Diff: removed neverallow rules."""
        rules = sorted(self.diff.removed_neverallows)
        self.assertEqual(2, len(rules))

        # removed rule with existing types
        self.validate_rule(rules[0], "neverallow", "na_removed_rule_source",
                           "na_removed_rule_target", "infoflow", set(["hi_r"]))

        # removed rule with new type
        self.validate_rule(rules[1], "neverallow", "removed_type", "removed_type", "removed_class",
                           set(["null_perm"]))

    def test_modified_neverallow_rules(self):
        """Diff: modified neverallow rules."""
        l = sorted(self.diff.modified_neverallows)
        self.assertEqual(3, len(l))

        # add permissions
        rule, added_perms, removed_perms, matched_perms = l[0]
        self.assertEqual("neverallow", rule.ruletype)
        self.assertEqual("na_modified_rule_add_perms", rule.source)
        self.assertEqual("na_modified_rule_add_perms", rule.target)
        self.assertEqual("infoflow", rule.tclass)
        self.assertSetEqual(set(["hi_w"]), added_perms)
        self.assertFalse(removed_perms)
        self.assertSetEqual(set(["hi_r"]), matched_perms)

        # add and remove permissions
        rule, added_perms, removed_perms, matched_perms = l[1]
        self.assertEqual("neverallow", rule.ruletype)
        self.assertEqual("na_modified_rule_add_remove_perms", rule.source)
        self.assertEqual("na_modified_rule_add_remove_perms", rule.target)
        self.assertEqual("infoflow2", rule.tclass)
        self.assertSetEqual(set(["super_r"]), added_perms)
        self.assertSetEqual(set(["super_w"]), removed_perms)
        self.assertSetEqual(set(["low_w"]), matched_perms)

        # remove permissions
        rule, added_perms, removed_perms, matched_perms = l[2]
        self.assertEqual("neverallow", rule.ruletype)
        self.assertEqual("na_modified_rule_remove_perms", rule.source)
        self.assertEqual("na_modified_rule_remove_perms", rule.target)
        self.assertEqual("infoflow", rule.tclass)
        self.assertFalse(added_perms)
        self.assertSetEqual(set(["low_r"]), removed_perms)
        self.assertSetEqual(set(["low_w"]), matched_perms)

    #
    # Type_transition rules
    #
    def test_added_type_transition_rules(self):
        """Diff: added type_transition rules."""
        rules = sorted(self.diff.added_type_transitions)
        self.assertEqual(5, len(rules))

        # added rule with new type
        self.validate_rule(rules[0], "type_transition", "added_type", "system", "infoflow4",
                           "system")

        # rule moved from one conditional block to another (true to false)
        self.validate_rule(rules[1], "type_transition", "system", "tt_switch_block", "infoflow6",
                           "system", cond="tt_switch_block_b", cond_block=False)

        # added rule with existing types
        self.validate_rule(rules[2], "type_transition", "tt_added_rule_source",
                           "tt_added_rule_target", "infoflow", "system")

        # rule moved out of a conditional
        self.validate_rule(rules[3], "type_transition", "tt_move_from_bool", "system",
                           "infoflow4", "system")

        # rule moved into a conditional
        self.validate_rule(rules[4], "type_transition", "tt_move_to_bool", "system",
                           "infoflow3", "system", cond="tt_move_to_bool_b", cond_block=True)

    def test_removed_type_transition_rules(self):
        """Diff: removed type_transition rules."""
        rules = sorted(self.diff.removed_type_transitions)
        self.assertEqual(5, len(rules))

        # removed rule with new type
        self.validate_rule(rules[0], "type_transition", "removed_type", "system", "infoflow4",
                           "system")

        # rule moved from one conditional block to another (true to false)
        self.validate_rule(rules[1], "type_transition", "system", "tt_switch_block", "infoflow6",
                           "system", cond="tt_switch_block_b", cond_block=True)

        # rule moved out of a conditional
        self.validate_rule(rules[2], "type_transition", "tt_move_from_bool", "system",
                           "infoflow4", "system", cond="tt_move_from_bool_b", cond_block=True)

        # rule moved into a conditional
        self.validate_rule(rules[3], "type_transition", "tt_move_to_bool", "system",
                           "infoflow3", "system")

        # removed rule with existing types
        self.validate_rule(rules[4], "type_transition", "tt_removed_rule_source",
                           "tt_removed_rule_target", "infoflow", "system")

    def test_modified_type_transition_rules(self):
        """Diff: modified type_transition rules."""
        l = sorted(self.diff.modified_type_transitions)
        self.assertEqual(1, len(l))

        rule, added_default, removed_default = l[0]
        self.assertEqual("type_transition", rule.ruletype)
        self.assertEqual("tt_matched_source", rule.source)
        self.assertEqual("system", rule.target)
        self.assertEqual("infoflow", rule.tclass)
        self.assertEqual("tt_new_type", added_default)
        self.assertEqual("tt_old_type", removed_default)

    #
    # Type_change rules
    #
    def test_added_type_change_rules(self):
        """Diff: added type_change rules."""
        rules = sorted(self.diff.added_type_changes)
        self.assertEqual(5, len(rules))

        # added rule with new type
        self.validate_rule(rules[0], "type_change", "added_type", "system", "infoflow4",
                           "system")

        # rule moved from one conditional block to another (true to false)
        self.validate_rule(rules[1], "type_change", "system", "tc_switch_block", "infoflow6",
                           "system", cond="tc_switch_block_b", cond_block=False)

        # added rule with existing types
        self.validate_rule(rules[2], "type_change", "tc_added_rule_source",
                           "tc_added_rule_target", "infoflow", "system")

        # rule moved out of a conditional
        self.validate_rule(rules[3], "type_change", "tc_move_from_bool", "system",
                           "infoflow4", "system")

        # rule moved into a conditional
        self.validate_rule(rules[4], "type_change", "tc_move_to_bool", "system",
                           "infoflow3", "system", cond="tc_move_to_bool_b", cond_block=True)

    def test_removed_type_change_rules(self):
        """Diff: removed type_change rules."""
        rules = sorted(self.diff.removed_type_changes)
        self.assertEqual(5, len(rules))

        # removed rule with new type
        self.validate_rule(rules[0], "type_change", "removed_type", "system", "infoflow4",
                           "system")

        # rule moved from one conditional block to another (true to false)
        self.validate_rule(rules[1], "type_change", "system", "tc_switch_block", "infoflow6",
                           "system", cond="tc_switch_block_b", cond_block=True)

        # rule moved out of a conditional
        self.validate_rule(rules[2], "type_change", "tc_move_from_bool", "system",
                           "infoflow4", "system", cond="tc_move_from_bool_b", cond_block=True)

        # rule moved into a conditional
        self.validate_rule(rules[3], "type_change", "tc_move_to_bool", "system",
                           "infoflow3", "system")

        # removed rule with existing types
        self.validate_rule(rules[4], "type_change", "tc_removed_rule_source",
                           "tc_removed_rule_target", "infoflow", "system")

    def test_modified_type_change_rules(self):
        """Diff: modified type_change rules."""
        l = sorted(self.diff.modified_type_changes)
        self.assertEqual(1, len(l))

        rule, added_default, removed_default = l[0]
        self.assertEqual("type_change", rule.ruletype)
        self.assertEqual("tc_matched_source", rule.source)
        self.assertEqual("system", rule.target)
        self.assertEqual("infoflow", rule.tclass)
        self.assertEqual("tc_new_type", added_default)
        self.assertEqual("tc_old_type", removed_default)

    #
    # Type_member rules
    #
    def test_added_type_member_rules(self):
        """Diff: added type_member rules."""
        rules = sorted(self.diff.added_type_members)
        self.assertEqual(5, len(rules))

        # added rule with new type
        self.validate_rule(rules[0], "type_member", "added_type", "system", "infoflow4",
                           "system")

        # rule moved from one conditional block to another (true to false)
        self.validate_rule(rules[1], "type_member", "system", "tm_switch_block", "infoflow6",
                           "system", cond="tm_switch_block_b", cond_block=False)

        # added rule with existing types
        self.validate_rule(rules[2], "type_member", "tm_added_rule_source",
                           "tm_added_rule_target", "infoflow", "system")

        # rule moved out of a conditional
        self.validate_rule(rules[3], "type_member", "tm_move_from_bool", "system",
                           "infoflow4", "system")

        # rule moved into a conditional
        self.validate_rule(rules[4], "type_member", "tm_move_to_bool", "system",
                           "infoflow3", "system", cond="tm_move_to_bool_b", cond_block=True)

    def test_removed_type_member_rules(self):
        """Diff: removed type_member rules."""
        rules = sorted(self.diff.removed_type_members)
        self.assertEqual(5, len(rules))

        # removed rule with new type
        self.validate_rule(rules[0], "type_member", "removed_type", "system", "infoflow4",
                           "system")

        # rule moved from one conditional block to another (true to false)
        self.validate_rule(rules[1], "type_member", "system", "tm_switch_block", "infoflow6",
                           "system", cond="tm_switch_block_b", cond_block=True)

        # rule moved out of a conditional
        self.validate_rule(rules[2], "type_member", "tm_move_from_bool", "system",
                           "infoflow4", "system", cond="tm_move_from_bool_b", cond_block=True)

        # rule moved into a conditional
        self.validate_rule(rules[3], "type_member", "tm_move_to_bool", "system",
                           "infoflow3", "system")

        # removed rule with existing types
        self.validate_rule(rules[4], "type_member", "tm_removed_rule_source",
                           "tm_removed_rule_target", "infoflow", "system")

    def test_modified_type_member_rules(self):
        """Diff: modified type_member rules."""
        l = sorted(self.diff.modified_type_members)
        self.assertEqual(1, len(l))

        rule, added_default, removed_default = l[0]
        self.assertEqual("type_member", rule.ruletype)
        self.assertEqual("tm_matched_source", rule.source)
        self.assertEqual("system", rule.target)
        self.assertEqual("infoflow", rule.tclass)
        self.assertEqual("tm_new_type", added_default)
        self.assertEqual("tm_old_type", removed_default)


class PolicyDifferenceTestNoDiff(unittest.TestCase):

    """Policy difference test with no policy differences."""

    def setUp(self):
        self.diff = PolicyDifference(SELinuxPolicy("tests/diff_left.conf"),
                                     SELinuxPolicy("tests/diff_left.conf"))

    def test_added_types(self):
        """NoDiff: no added types"""
        self.assertFalse(self.diff.added_types)

    def test_removed_types(self):
        """NoDiff: no removed types"""
        self.assertFalse(self.diff.removed_types)

    def test_modified_types(self):
        """NoDiff: no modified types"""
        self.assertFalse(self.diff.modified_types)

    def test_added_roles(self):
        """NoDiff: no added roles."""
        self.assertFalse(self.diff.added_roles)

    def test_removed_roles(self):
        """NoDiff: no removed roles."""
        self.assertFalse(self.diff.removed_roles)

    def test_modified_roles(self):
        """NoDiff: no modified roles."""
        self.assertFalse(self.diff.modified_roles)

    def test_added_commons(self):
        """NoDiff: no added commons."""
        self.assertFalse(self.diff.added_commons)

    def test_removed_commons(self):
        """NoDiff: no removed commons."""
        self.assertFalse(self.diff.removed_commons)

    def test_modified_commons(self):
        """NoDiff: no modified commons."""
        self.assertFalse(self.diff.modified_commons)

    def test_added_classes(self):
        """NoDiff: no added classes."""
        self.assertFalse(self.diff.added_classes)

    def test_removed_classes(self):
        """NoDiff: no removed classes."""
        self.assertFalse(self.diff.removed_classes)

    def test_modified_classes(self):
        """NoDiff: no modified classes."""
        self.assertFalse(self.diff.modified_classes)

    def test_added_allows(self):
        """NoDiff: no added allow rules."""
        self.assertFalse(self.diff.added_allows)

    def test_removed_allows(self):
        """NoDiff: no removed allow rules."""
        self.assertFalse(self.diff.removed_allows)

    def test_modified_allows(self):
        """NoDiff: no modified allow rules."""
        self.assertFalse(self.diff.modified_allows)

    def test_added_auditallows(self):
        """NoDiff: no added auditallow rules."""
        self.assertFalse(self.diff.added_auditallows)

    def test_removed_auditallows(self):
        """NoDiff: no removed auditallow rules."""
        self.assertFalse(self.diff.removed_auditallows)

    def test_modified_auditallows(self):
        """NoDiff: no modified auditallow rules."""
        self.assertFalse(self.diff.modified_auditallows)

    def test_added_neverallows(self):
        """NoDiff: no added neverallow rules."""
        self.assertFalse(self.diff.added_neverallows)

    def test_removed_neverallows(self):
        """NoDiff: no removed neverallow rules."""
        self.assertFalse(self.diff.removed_neverallows)

    def test_modified_neverallows(self):
        """NoDiff: no modified neverallow rules."""
        self.assertFalse(self.diff.modified_neverallows)

    def test_added_dontaudits(self):
        """NoDiff: no added dontaudit rules."""
        self.assertFalse(self.diff.added_dontaudits)

    def test_removed_dontaudits(self):
        """NoDiff: no removed dontaudit rules."""
        self.assertFalse(self.diff.removed_dontaudits)

    def test_modified_dontaudits(self):
        """NoDiff: no modified dontaudit rules."""
        self.assertFalse(self.diff.modified_dontaudits)

    def test_added_type_transitions(self):
        """NoDiff: no added type_transition rules."""
        self.assertFalse(self.diff.added_type_transitions)

    def test_removed_type_transitions(self):
        """NoDiff: no removed type_transition rules."""
        self.assertFalse(self.diff.removed_type_transitions)

    def test_modified_type_transitions(self):
        """NoDiff: no modified type_transition rules."""
        self.assertFalse(self.diff.modified_type_transitions)

    def test_added_type_changes(self):
        """NoDiff: no added type_change rules."""
        self.assertFalse(self.diff.added_type_changes)

    def test_removed_type_changes(self):
        """NoDiff: no removed type_change rules."""
        self.assertFalse(self.diff.removed_type_changes)

    def test_modified_type_changes(self):
        """NoDiff: no modified type_change rules."""
        self.assertFalse(self.diff.modified_type_changes)

    def test_added_type_members(self):
        """NoDiff: no added type_member rules."""
        self.assertFalse(self.diff.added_type_members)

    def test_removed_type_members(self):
        """NoDiff: no removed type_member rules."""
        self.assertFalse(self.diff.removed_type_members)

    def test_modified_type_members(self):
        """NoDiff: no modified type_member rules."""
        self.assertFalse(self.diff.modified_type_members)
