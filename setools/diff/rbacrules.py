# Copyright 2016, Tresys Technology, LLC
# Copyright 2018, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from collections import defaultdict
from typing import NamedTuple

from ..policyrep import AnyRBACRule, RBACRuletype, Role, RoleAllow, RoleTransition

from .descriptors import DiffResultDescriptor
from .difference import Difference, Wrapper
from .objclass import class_wrapper_factory
from .roles import role_wrapper_factory
from .types import type_or_attr_wrapper_factory
from .typing import RuleList


class ModifiedRBACRule(NamedTuple):

    """Difference details for a modified RBAC rule."""

    rule: AnyRBACRule
    added_default: Role
    removed_default: Role


class RBACRulesDifference(Difference):

    """Determine the difference in RBAC rules between two policies."""

    added_role_allows = DiffResultDescriptor("diff_role_allows")
    removed_role_allows = DiffResultDescriptor("diff_role_allows")
    # role allows cannot be modified, only added/removed

    added_role_transitions = DiffResultDescriptor("diff_role_transitions")
    removed_role_transitions = DiffResultDescriptor("diff_role_transitions")
    modified_role_transitions = DiffResultDescriptor("diff_role_transitions")

    # Lists of rules for each policy
    _left_rbac_rules: RuleList[RBACRuletype, AnyRBACRule] = None
    _right_rbac_rules: RuleList[RBACRuletype, AnyRBACRule] = None

    def diff_role_allows(self) -> None:
        """Generate the difference in role allow rules between the policies."""

        self.log.info(
            "Generating role allow differences from {0.left_policy} to {0.right_policy}".
            format(self))

        if self._left_rbac_rules is None or self._right_rbac_rules is None:
            self._create_rbac_rule_lists()

        assert self._left_rbac_rules is not None, "Left RBAC rules didn't load, this a bug."
        assert self._right_rbac_rules is not None, "Right RBAC rules didn't load, this a bug."

        self.added_role_allows, self.removed_role_allows, _ = self._set_diff(
            self._expand_generator(self._left_rbac_rules[RBACRuletype.allow], RoleAllowWrapper),
            self._expand_generator(self._right_rbac_rules[RBACRuletype.allow], RoleAllowWrapper))

    def diff_role_transitions(self) -> None:
        """Generate the difference in role_transition rules between the policies."""

        self.log.info(
            "Generating role_transition differences from {0.left_policy} to {0.right_policy}".
            format(self))

        if self._left_rbac_rules is None or self._right_rbac_rules is None:
            self._create_rbac_rule_lists()

        assert self._left_rbac_rules is not None, "Left RBAC rules didn't load, this a bug."
        assert self._right_rbac_rules is not None, "Right RBAC rules didn't load, this a bug."

        added, removed, matched = self._set_diff(
            self._expand_generator(self._left_rbac_rules[RBACRuletype.role_transition],
                                   RoleTransitionWrapper),
            self._expand_generator(self._right_rbac_rules[RBACRuletype.role_transition],
                                   RoleTransitionWrapper))

        modified = []
        for left_rule, right_rule in matched:
            # Criteria for modified rules
            # 1. change to default role
            if role_wrapper_factory(left_rule.default) != role_wrapper_factory(right_rule.default):
                modified.append(ModifiedRBACRule(left_rule,
                                                 right_rule.default,
                                                 left_rule.default))

        self.added_role_transitions = added
        self.removed_role_transitions = removed
        self.modified_role_transitions = modified

    #
    # Internal functions
    #
    def _create_rbac_rule_lists(self) -> None:
        """Create rule lists for both policies."""
        # do not expand yet, to keep memory
        # use down as long as possible
        self._left_rbac_rules = defaultdict(list)
        self.log.debug("Building RBAC rule lists from {0.left_policy}".format(self))
        for rule in self.left_policy.rbacrules():
            self._left_rbac_rules[rule.ruletype].append(rule)

        self._right_rbac_rules = defaultdict(list)
        self.log.debug("Building RBAC rule lists from {0.right_policy}".format(self))
        for rule in self.right_policy.rbacrules():
            self._right_rbac_rules[rule.ruletype].append(rule)

        self.log.debug("Completed building RBAC rule lists.")

    def _reset_diff(self) -> None:
        """Reset diff results on policy changes."""
        self.log.debug("Resetting RBAC rule differences")
        self.added_role_allows = None
        self.removed_role_allows = None
        self.added_role_transitions = None
        self.removed_role_transitions = None
        self.modified_role_transitions = None

        # Sets of rules for each policy
        self._left_rbac_rules = None
        self._right_rbac_rules = None


class RoleAllowWrapper(Wrapper[RoleAllow]):

    """Wrap role allow rules to allow set operations."""

    __slots__ = ("source", "target")

    def __init__(self, rule: RoleAllow) -> None:
        self.origin = rule
        self.source = role_wrapper_factory(rule.source)
        self.target = role_wrapper_factory(rule.target)
        self.key = hash(rule)

    def __hash__(self):
        return self.key

    def __lt__(self, other):
        return self.key < other.key

    def __eq__(self, other):
        # because RBACRuleDifference groups rules by ruletype,
        # the ruletype always matches.
        return self.source == other.source and self.target == other.target


class RoleTransitionWrapper(Wrapper[RoleTransition]):

    """Wrap role_transition rules to allow set operations."""

    __slots__ = ("source", "target", "tclass")

    def __init__(self, rule: RoleTransition) -> None:
        self.origin = rule
        self.source = role_wrapper_factory(rule.source)
        self.target = type_or_attr_wrapper_factory(rule.target)
        self.tclass = class_wrapper_factory(rule.tclass)
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
