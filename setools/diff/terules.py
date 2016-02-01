# Copyright 2015-2016, Tresys Technology, LLC
#
# This file is part of SETools.
#
# SETools is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation, either version 2.1 of
# the License, or (at your option) any later version.
#
# SETools is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with SETools.  If not, see
# <http://www.gnu.org/licenses/>.
#
from collections import namedtuple

from ..policyrep.exception import RuleNotConditional, RuleUseError, TERuleNoFilename

from .conditional import ConditionalExprWrapper
from .descriptors import DiffResultDescriptor
from .difference import Difference, SymbolWrapper, Wrapper


modified_avrule_record = namedtuple("modified_avrule", ["rule",
                                                        "added_perms",
                                                        "removed_perms",
                                                        "matched_perms"])

modified_terule_record = namedtuple("modified_terule", ["rule", "added_default", "removed_default"])


class TERulesDifference(Difference):

    """
    Determine the difference in type enforcement rules
    between two policies.
    """

    added_allows = DiffResultDescriptor("diff_allows")
    removed_allows = DiffResultDescriptor("diff_allows")
    modified_allows = DiffResultDescriptor("diff_allows")

    added_auditallows = DiffResultDescriptor("diff_auditallows")
    removed_auditallows = DiffResultDescriptor("diff_auditallows")
    modified_auditallows = DiffResultDescriptor("diff_auditallows")

    added_neverallows = DiffResultDescriptor("diff_neverallows")
    removed_neverallows = DiffResultDescriptor("diff_neverallows")
    modified_neverallows = DiffResultDescriptor("diff_neverallows")

    added_dontaudits = DiffResultDescriptor("diff_dontaudits")
    removed_dontaudits = DiffResultDescriptor("diff_dontaudits")
    modified_dontaudits = DiffResultDescriptor("diff_dontaudits")

    added_type_transitions = DiffResultDescriptor("diff_type_transitions")
    removed_type_transitions = DiffResultDescriptor("diff_type_transitions")
    modified_type_transitions = DiffResultDescriptor("diff_type_transitions")

    added_type_changes = DiffResultDescriptor("diff_type_changes")
    removed_type_changes = DiffResultDescriptor("diff_type_changes")
    modified_type_changes = DiffResultDescriptor("diff_type_changes")

    added_type_members = DiffResultDescriptor("diff_type_members")
    removed_type_members = DiffResultDescriptor("diff_type_members")
    modified_type_members = DiffResultDescriptor("diff_type_members")

    # Lists of rules for each policy
    _left_allows = None
    _right_allows = None

    _left_auditallows = None
    _right_auditallows = None

    _left_neverallows = None
    _right_neverallows = None

    _left_dontaudits = None
    _right_dontaudits = None

    _left_type_transitions = None
    _right_type_transitions = None

    _left_type_changes = None
    _right_type_changes = None

    _left_type_members = None
    _right_type_members = None

    def diff_allows(self):
        """Generate the difference in allow rules between the policies."""

        self.log.info(
            "Generating allow differences from {0.left_policy} to {0.right_policy}".format(self))

        if self._left_allows is None or self._right_allows is None:
            self._create_te_rule_lists()

        self.added_allows, self.removed_allows, self.modified_allows = self._diff_av_rules(
            self._expand_generator(self._left_allows, AVRuleWrapper),
            self._expand_generator(self._right_allows, AVRuleWrapper))

    def diff_auditallows(self):
        """Generate the difference in auditallow rules between the policies."""

        self.log.info(
            "Generating auditallow differences from {0.left_policy} to {0.right_policy}".
            format(self))

        if self._left_auditallows is None or self._right_auditallows is None:
            self._create_te_rule_lists()

        self.added_auditallows, \
            self.removed_auditallows, \
            self.modified_auditallows = self._diff_av_rules(
                self._expand_generator(self._left_auditallows, AVRuleWrapper),
                self._expand_generator(self._right_auditallows, AVRuleWrapper))

    def diff_neverallows(self):
        """Generate the difference in neverallow rules between the policies."""

        self.log.info(
            "Generating neverallow differences from {0.left_policy} to {0.right_policy}".
            format(self))

        if self._left_neverallows is None or self._right_neverallows is None:
            self._create_te_rule_lists()

        self.added_neverallows, \
            self.removed_neverallows, \
            self.modified_neverallows = self._diff_av_rules(
                self._expand_generator(self._left_neverallows, AVRuleWrapper),
                self._expand_generator(self._right_neverallows, AVRuleWrapper))

    def diff_dontaudits(self):
        """Generate the difference in dontaudit rules between the policies."""

        self.log.info(
            "Generating dontaudit differences from {0.left_policy} to {0.right_policy}".
            format(self))

        if self._left_dontaudits is None or self._right_dontaudits is None:
            self._create_te_rule_lists()

        self.added_dontaudits, \
            self.removed_dontaudits, \
            self.modified_dontaudits = self._diff_av_rules(
                self._expand_generator(self._left_dontaudits, AVRuleWrapper),
                self._expand_generator(self._right_dontaudits, AVRuleWrapper))

    def diff_type_transitions(self):
        """Generate the difference in type_transition rules between the policies."""

        self.log.info(
            "Generating type_transition differences from {0.left_policy} to {0.right_policy}".
            format(self))

        if self._left_type_transitions is None or self._right_type_transitions is None:
            self._create_te_rule_lists()

        self.added_type_transitions, \
            self.removed_type_transitions, \
            self.modified_type_transitions = self._diff_te_rules(
                self._expand_generator(self._left_type_transitions, TERuleWrapper),
                self._expand_generator(self._right_type_transitions, TERuleWrapper))

    def diff_type_changes(self):
        """Generate the difference in type_change rules between the policies."""

        self.log.info(
            "Generating type_change differences from {0.left_policy} to {0.right_policy}".
            format(self))

        if self._left_type_changes is None or self._right_type_changes is None:
            self._create_te_rule_lists()

        self.added_type_changes, \
            self.removed_type_changes, \
            self.modified_type_changes = self._diff_te_rules(
                self._expand_generator(self._left_type_changes, TERuleWrapper),
                self._expand_generator(self._right_type_changes, TERuleWrapper))

    def diff_type_members(self):
        """Generate the difference in type_member rules between the policies."""

        self.log.info(
            "Generating type_member differences from {0.left_policy} to {0.right_policy}".
            format(self))

        if self._left_type_members is None or self._right_type_members is None:
            self._create_te_rule_lists()

        self.added_type_members, \
            self.removed_type_members, \
            self.modified_type_members = self._diff_te_rules(
                self._expand_generator(self._left_type_members, TERuleWrapper),
                self._expand_generator(self._right_type_members, TERuleWrapper))

    #
    # Internal functions
    #
    def _create_te_rule_lists(self):
        """Create rule lists for both policies."""

        self._left_allows = []
        self._left_auditallows = []
        self._left_neverallows = []
        self._left_dontaudits = []
        self._left_type_transitions = []
        self._left_type_changes = []
        self._left_type_members = []
        for rule in self.left_policy.terules():
            # do not expand yet, to keep memory
            # use down as long as possible
            if rule.ruletype == "allow":
                self._left_allows.append(rule)
            elif rule.ruletype == "auditallow":
                self._left_auditallows.append(rule)
            elif rule.ruletype == "neverallow":
                self._left_neverallows.append(rule)
            elif rule.ruletype == "dontaudit":
                self._left_dontaudits.append(rule)
            elif rule.ruletype == "type_transition":
                self._left_type_transitions.append(rule)
            elif rule.ruletype == "type_change":
                self._left_type_changes.append(rule)
            elif rule.ruletype == "type_member":
                self._left_type_members.append(rule)
            else:
                self.log.error("Unknown rule type: {0} (This is an SETools bug)".
                               format(rule.ruletype))

        self._right_allows = []
        self._right_auditallows = []
        self._right_neverallows = []
        self._right_dontaudits = []
        self._right_type_transitions = []
        self._right_type_changes = []
        self._right_type_members = []
        for rule in self.right_policy.terules():
            # do not expand yet, to keep memory
            # use down as long as possible
            if rule.ruletype == "allow":
                self._right_allows.append(rule)
            elif rule.ruletype == "auditallow":
                self._right_auditallows.append(rule)
            elif rule.ruletype == "neverallow":
                self._right_neverallows.append(rule)
            elif rule.ruletype == "dontaudit":
                self._right_dontaudits.append(rule)
            elif rule.ruletype == "type_transition":
                self._right_type_transitions.append(rule)
            elif rule.ruletype == "type_change":
                self._right_type_changes.append(rule)
            elif rule.ruletype == "type_member":
                self._right_type_members.append(rule)
            else:
                self.log.error("Unknown rule type: {0} (This is an SETools bug)".
                               format(rule.ruletype))

    def _diff_av_rules(self, left_list, right_list):
        """Common method for comparing access vector rules."""
        added, removed, matched = self._set_diff(left_list, right_list)

        modified = []

        for left_rule, right_rule in matched:
            # Criteria for modified rules
            # 1. change to permissions
            added_perms, removed_perms, matched_perms = self._set_diff(left_rule.perms,
                                                                       right_rule.perms)

            # the final set comprehension is to avoid having lists
            # like [("perm1", "perm1"), ("perm2", "perm2")], as the
            # matched_perms return from _set_diff is a set of tuples
            if added_perms or removed_perms:
                modified.append(modified_avrule_record(left_rule,
                                                       added_perms,
                                                       removed_perms,
                                                       set(p[0] for p in matched_perms)))

        return added, removed, modified

    def _diff_te_rules(self, left_list, right_list):
        """Common method for comparing type_* rules."""
        added, removed, matched = self._set_diff(left_list, right_list)

        modified = []

        for left_rule, right_rule in matched:
            # Criteria for modified rules
            # 1. change to default type
            if SymbolWrapper(left_rule.default) != SymbolWrapper(right_rule.default):
                modified.append(modified_terule_record(left_rule,
                                                       right_rule.default,
                                                       left_rule.default))

        return added, removed, modified

    def _reset_diff(self):
        """Reset diff results on policy changes."""
        self.log.debug("Resetting TE rule differences")
        self.added_allows = None
        self.removed_allows = None
        self.modified_allows = None
        self.added_auditallows = None
        self.removed_auditallows = None
        self.modified_auditallows = None
        self.added_neverallows = None
        self.removed_neverallows = None
        self.modified_neverallows = None
        self.added_dontaudits = None
        self.removed_dontaudits = None
        self.modified_dontaudits = None
        self.added_type_transitions = None
        self.removed_type_transitions = None
        self.modified_type_transitions = None
        self.added_type_changes = None
        self.removed_type_changes = None
        self.modified_type_changes = None
        self.added_type_members = None
        self.removed_type_members = None
        self.modified_type_members = None

        # Sets of rules for each policy
        self._left_allows = None
        self._right_allows = None
        self._left_auditallows = None
        self._right_auditallows = None
        self._left_neverallows = None
        self._right_neverallows = None
        self._left_dontaudits = None
        self._right_dontaudits = None
        self._left_type_transitions = None
        self._right_type_transitions = None
        self._left_type_changes = None
        self._right_type_changes = None
        self._left_type_members = None
        self._right_type_members = None


class AVRuleWrapper(Wrapper):

    """Wrap access vector rules to allow set operations."""

    def __init__(self, rule):
        self.origin = rule
        self.ruletype = rule.ruletype
        self.source = SymbolWrapper(rule.source)
        self.target = SymbolWrapper(rule.target)
        self.tclass = SymbolWrapper(rule.tclass)
        self.key = hash(rule)

        try:
            self.conditional = ConditionalExprWrapper(rule.conditional)
            self.conditional_block = rule.conditional_block
        except RuleNotConditional:
            self.conditional = None
            self.conditional_block = None

    def __hash__(self):
        return self.key

    def __lt__(self, other):
        return self.key < other.key

    def __eq__(self, other):
        # because TERuleDifference groups rules by ruletype,
        # the ruletype always matches.
        return self.source == other.source and \
               self.target == other.target and \
               self.tclass == other.tclass and \
               self.conditional == other.conditional and \
               self.conditional_block == other.conditional_block


class TERuleWrapper(Wrapper):

    """Wrap type_* rules to allow set operations."""

    def __init__(self, rule):
        self.origin = rule
        self.ruletype = rule.ruletype
        self.source = SymbolWrapper(rule.source)
        self.target = SymbolWrapper(rule.target)
        self.tclass = SymbolWrapper(rule.tclass)
        self.key = hash(rule)

        try:
            self.conditional = ConditionalExprWrapper(rule.conditional)
            self.conditional_block = rule.conditional_block
        except RuleNotConditional:
            self.conditional = None
            self.conditional_block = None

        try:
            self.filename = rule.filename
        except (RuleUseError, TERuleNoFilename):
            self.filename = None

    def __hash__(self):
        return self.key

    def __lt__(self, other):
        return self.key < other.key

    def __eq__(self, other):
        # because TERuleDifference groups rules by ruletype,
        # the ruletype always matches.
        return self.source == other.source and \
               self.target == other.target and \
               self.tclass == other.tclass and \
               self.conditional == other.conditional and \
               self.conditional_block == other.conditional_block and \
               self.filename == self.filename
