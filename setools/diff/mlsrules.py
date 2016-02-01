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
from .mls import RangeWrapper


modified_mlsrule_record = namedtuple("modified_mlsrule", ["rule",
                                                          "added_default",
                                                          "removed_default"])


class MLSRulesDifference(Difference):

    """Determine the difference in MLS rules between two policies."""

    added_range_transitions = DiffResultDescriptor("diff_range_transitions")
    removed_range_transitions = DiffResultDescriptor("diff_range_transitions")
    modified_range_transitions = DiffResultDescriptor("diff_range_transitions")

    # Lists of rules for each policy
    _left_range_transitions = None
    _right_range_transitions = None

    def diff_range_transitions(self):
        """Generate the difference in range_transition rules between the policies."""

        self.log.info(
            "Generating range_transition differences from {0.left_policy} to {0.right_policy}".
            format(self))

        if self._left_range_transitions is None or self._right_range_transitions is None:
            self._create_mls_rule_lists()

        self.added_range_transitions, \
            self.removed_range_transitions, \
            self.modified_range_transitions = self._diff_mls_rules(
                self._expand_generator(self._left_range_transitions, MLSRuleWrapper),
                self._expand_generator(self._right_range_transitions, MLSRuleWrapper))

    #
    # Internal functions
    #
    def _create_mls_rule_lists(self):
        """Create rule lists for both policies."""
        self._left_range_transitions = []
        for rule in self.left_policy.mlsrules():
            # do not expand yet, to keep memory
            # use down as long as possible
            if rule.ruletype == "range_transition":
                self._left_range_transitions.append(rule)
            else:
                self.log.error("Unknown rule type: {0} (This is an SETools bug)".
                               format(rule.ruletype))

        self._right_range_transitions = []
        for rule in self.right_policy.mlsrules():
            # do not expand yet, to keep memory
            # use down as long as possible
            if rule.ruletype == "range_transition":
                self._right_range_transitions.append(rule)
            else:
                self.log.error("Unknown rule type: {0} (This is an SETools bug)".
                               format(rule.ruletype))

    def _diff_mls_rules(self, left_list, right_list):
        """Common method for comparing type_* rules."""
        added, removed, matched = self._set_diff(left_list, right_list)

        modified = []

        for left_rule, right_rule in matched:
            # Criteria for modified rules
            # 1. change to default range
            if RangeWrapper(left_rule.default) != RangeWrapper(right_rule.default):
                modified.append(modified_mlsrule_record(left_rule,
                                                        right_rule.default,
                                                        left_rule.default))

        return added, removed, modified

    def _reset_diff(self):
        """Reset diff results on policy changes."""
        self.log.debug("Resetting MLS rule differences")
        self.added_range_transitions = None
        self.removed_range_transitions = None
        self.modified_range_transitions = None

        # Sets of rules for each policy
        self._left_range_transitions = None
        self._right_range_transitions = None


class MLSRuleWrapper(Wrapper):

    """Wrap MLS rules to allow set operations."""

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
        # because MLSRuleDifference groups rules by ruletype,
        # the ruletype always matches.
        return self.source == other.source and \
               self.target == other.target and \
               self.tclass == other.tclass
