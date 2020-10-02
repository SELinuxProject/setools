# Copyright 2016, Tresys Technology, LLC
# Copyright 2018, Chris PeBenito <pebenito@ieee.org>
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
from collections import defaultdict
from typing import NamedTuple

from ..policyrep import MLSRule, MLSRuletype, Range

from .descriptors import DiffResultDescriptor
from .difference import Difference, Wrapper
from .mls import RangeWrapper
from .objclass import class_wrapper_factory
from .types import type_or_attr_wrapper_factory
from .typing import RuleList


class ModifiedMLSRule(NamedTuple):

    """Difference details for a modified MLS rule."""

    rule: MLSRule
    added_default: Range
    removed_default: Range


class MLSRulesDifference(Difference):

    """Determine the difference in MLS rules between two policies."""

    added_range_transitions = DiffResultDescriptor("diff_range_transitions")
    removed_range_transitions = DiffResultDescriptor("diff_range_transitions")
    modified_range_transitions = DiffResultDescriptor("diff_range_transitions")

    # Lists of rules for each policy
    _left_mls_rules: RuleList[MLSRuletype, MLSRule] = None
    _right_mls_rules: RuleList[MLSRuletype, MLSRule] = None

    def diff_range_transitions(self) -> None:
        """Generate the difference in range_transition rules between the policies."""

        self.log.info(
            "Generating range_transition differences from {0.left_policy} to {0.right_policy}".
            format(self))

        if self._left_mls_rules is None or self._right_mls_rules is None:
            self._create_mls_rule_lists()

        assert self._left_mls_rules is not None, "Left MLS rules did not load, this is a bug."
        assert self._right_mls_rules is not None, "Right MLS rules did not load, this is a bug."

        added, removed, matched = self._set_diff(
            self._expand_generator(self._left_mls_rules[MLSRuletype.range_transition],
                                   MLSRuleWrapper),
            self._expand_generator(self._right_mls_rules[MLSRuletype.range_transition],
                                   MLSRuleWrapper))

        modified = []

        for left_rule, right_rule in matched:
            # Criteria for modified rules
            # 1. change to default range
            if RangeWrapper(left_rule.default) != RangeWrapper(right_rule.default):
                modified.append(ModifiedMLSRule(left_rule,
                                                right_rule.default,
                                                left_rule.default))

        self.added_range_transitions = added
        self.removed_range_transitions = removed
        self.modified_range_transitions = modified

    #
    # Internal functions
    #
    def _create_mls_rule_lists(self) -> None:
        """Create rule lists for both policies."""
        # do not expand yet, to keep memory
        # use down as long as possible
        self._left_mls_rules = defaultdict(list)
        self.log.debug("Building MLS rule lists from {0.left_policy}".format(self))
        for rule in self.left_policy.mlsrules():
            self._left_mls_rules[rule.ruletype].append(rule)

        self._right_mls_rules = defaultdict(list)
        self.log.debug("Building MLS rule lists from {0.right_policy}".format(self))
        for rule in self.right_policy.mlsrules():
            self._right_mls_rules[rule.ruletype].append(rule)

        self.log.debug("Completed building MLS rule lists.")

    def _reset_diff(self) -> None:
        """Reset diff results on policy changes."""
        self.log.debug("Resetting MLS rule differences")
        self.added_range_transitions = None
        self.removed_range_transitions = None
        self.modified_range_transitions = None

        # Sets of rules for each policy
        self._left_mls_rules = None
        self._right_mls_rules = None


# Pylint bug: https://github.com/PyCQA/pylint/issues/2822
class MLSRuleWrapper(Wrapper[MLSRule]):  # pylint: disable=unsubscriptable-object

    """Wrap MLS rules to allow set operations."""

    __slots__ = ("ruletype", "source", "target", "tclass")

    def __init__(self, rule: MLSRule) -> None:
        self.origin = rule
        self.source = type_or_attr_wrapper_factory(rule.source)
        self.target = type_or_attr_wrapper_factory(rule.target)
        self.tclass = class_wrapper_factory(rule.tclass)
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
