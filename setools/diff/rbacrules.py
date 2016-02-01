# Copyright 2016, Tresys Technology, LLC
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

from .descriptors import DiffResultDescriptor
from .difference import Difference, SymbolWrapper, Wrapper


modified_rbacrule_record = namedtuple("modified_rbacrule", ["rule",
                                                            "added_default",
                                                            "removed_default"])


class RBACRulesDifference(Difference):

    """Determine the difference in RBAC rules between two policies."""

    added_role_allows = DiffResultDescriptor("diff_role_allows")
    removed_role_allows = DiffResultDescriptor("diff_role_allows")
    # role allows cannot be modified, only added/removed

    added_role_transitions = DiffResultDescriptor("diff_role_transitions")
    removed_role_transitions = DiffResultDescriptor("diff_role_transitions")
    modified_role_transitions = DiffResultDescriptor("diff_role_transitions")

    # Lists of rules for each policy
    _left_role_allows = None
    _right_role_allows = None

    _left_role_transitions = None
    _right_role_transitions = None

    def diff_role_allows(self):
        """Generate the difference in role allow rules between the policies."""

        self.log.info(
            "Generating role allow differences from {0.left_policy} to {0.right_policy}".
            format(self))

        if self._left_role_allows is None or self._right_role_allows is None:
            self._create_rbac_rule_lists()

        self.added_role_allows, self.removed_role_allows, _ = \
            self._set_diff(self._expand_generator(self._left_role_allows, RoleAllowWrapper),
                           self._expand_generator(self._right_role_allows, RoleAllowWrapper))

    def diff_role_transitions(self):
        """Generate the difference in role_transition rules between the policies."""

        self.log.info(
            "Generating role_transition differences from {0.left_policy} to {0.right_policy}".
            format(self))

        if self._left_role_transitions is None or self._right_role_transitions is None:
            self._create_rbac_rule_lists()

        self.added_role_transitions, \
            self.removed_role_transitions, \
            self.modified_role_transitions = self._diff_rbac_rules(
                self._expand_generator(self._left_role_transitions, RoleTransitionWrapper),
                self._expand_generator(self._right_role_transitions, RoleTransitionWrapper))

    #
    # Internal functions
    #
    def _create_rbac_rule_lists(self):
        """Create rule lists for both policies."""
        self._left_role_allows = []
        self._left_role_transitions = []
        for rule in self.left_policy.rbacrules():
            # do not expand yet, to keep memory
            # use down as long as possible
            if rule.ruletype == "allow":
                self._left_role_allows.append(rule)
            elif rule.ruletype == "role_transition":
                self._left_role_transitions.append(rule)
            else:
                self.log.error("Unknown rule type: {0} (This is an SETools bug)".
                               format(rule.ruletype))

        self._right_role_allows = []
        self._right_role_transitions = []
        for rule in self.right_policy.rbacrules():
            # do not expand yet, to keep memory
            # use down as long as possible
            if rule.ruletype == "allow":
                self._right_role_allows.append(rule)
            elif rule.ruletype == "role_transition":
                self._right_role_transitions.append(rule)
            else:
                self.log.error("Unknown rule type: {0} (This is an SETools bug)".
                               format(rule.ruletype))

    def _diff_rbac_rules(self, left_list, right_list):
        """Common method for comparing rbac rules."""
        added, removed, matched = self._set_diff(left_list, right_list)

        modified = []

        for left_rule, right_rule in matched:
            # Criteria for modified rules
            # 1. change to default role
            if SymbolWrapper(left_rule.default) != SymbolWrapper(right_rule.default):
                modified.append(modified_rbacrule_record(left_rule,
                                                         right_rule.default,
                                                         left_rule.default))

        return added, removed, modified

    def _reset_diff(self):
        """Reset diff results on policy changes."""
        self.log.debug("Resetting RBAC rule differences")
        self.added_role_allows = None
        self.removed_role_allows = None
        self.modified_role_allows = None
        self.added_role_transitions = None
        self.removed_role_transitions = None
        self.modified_role_transitions = None

        # Sets of rules for each policy
        self._left_role_allows = None
        self._right_role_allows = None
        self._left_role_transitions = None
        self._right_role_transitions = None


class RoleAllowWrapper(Wrapper):

    """Wrap role allow rules to allow set operations."""

    def __init__(self, rule):
        self.origin = rule
        self.ruletype = rule.ruletype
        self.source = SymbolWrapper(rule.source)
        self.target = SymbolWrapper(rule.target)
        self.key = hash(rule)

    def __hash__(self):
        return self.key

    def __lt__(self, other):
        return self.key < other.key

    def __eq__(self, other):
        # because RBACRuleDifference groups rules by ruletype,
        # the ruletype always matches.
        return self.source == other.source and self.target == other.target


class RoleTransitionWrapper(Wrapper):

    """Wrap role_transition rules to allow set operations."""

    def __init__(self, rule):
        self.origin = rule
        self.ruletype = rule.ruletype
        self.source = SymbolWrapper(rule.source)
        self.target = SymbolWrapper(rule.target)
        self.tclass = SymbolWrapper(rule.tclass)
        self.key = hash(rule)

    def __hash__(self):
        return self.key

    def __lt__(self, other):
        return self.key < other.key

    def __eq__(self, other):
        # because RBACRuleDifference groups rules by ruletype,
        # the ruletype always matches.
        return self.source == other.source and \
               self.target == other.target and \
               self.tclass == other.tclass
