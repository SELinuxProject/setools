# Copyright 2016, Tresys Technology, LLC
# Copyright 2018, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from collections import defaultdict

from .. import policyrep

from .descriptors import DiffResultDescriptor
from .difference import Difference, SymbolWrapper, Wrapper
from .objclass import class_wrapper_factory
from .typing import RuleList


class ConstraintsDifference(Difference):

    """
    Determine the difference in constraints between two policies.

    Since the compiler does not union constraints, there may be multiple
    constraints with the same ruletype, object class, and permission
    set, so constraints can only be added or removed, not modified.

    The constraint expressions are compared only on a basic level.
    Expressions that are logically equivalent but are structurally
    different, for example, by associativity, will be considered
    different.  Type and role attributes are also not expanded,
    so if there are changes to attribute members, it will not
    be reflected as a difference.
    """

    def diff_constrains(self) -> None:
        """Generate the difference in constraint rules between the policies."""

        self.log.info(
            f"Generating constraint differences from {self.left_policy} to {self.right_policy}")

        if self._left_constraints is None or self._right_constraints is None:
            self._create_constrain_lists()

        assert self._left_constraints is not None, "Left constraints didn't load, this a bug."
        assert self._right_constraints is not None, "Right constraints didn't load, this a bug."

        self.added_constrains, self.removed_constrains, _ = self._set_diff(
            (ConstraintWrapper(c) for c in self._left_constraints[
                policyrep.ConstraintRuletype.constrain]),
            (ConstraintWrapper(c) for c in self._right_constraints[
                policyrep.ConstraintRuletype.constrain]))

    def diff_mlsconstrains(self) -> None:
        """Generate the difference in MLS constraint rules between the policies."""

        self.log.info(
            f"Generating MLS constraint differences from {self.left_policy} "
            f"to {self.right_policy}")

        if self._left_constraints is None or self._right_constraints is None:
            self._create_constrain_lists()

        assert self._left_constraints is not None, "Left constraints didn't load, this a bug."
        assert self._right_constraints is not None, "Right constraints didn't load, this a bug."

        self.added_mlsconstrains, self.removed_mlsconstrains, _ = self._set_diff(
            (ConstraintWrapper(c) for c in self._left_constraints[
                policyrep.ConstraintRuletype.mlsconstrain]),
            (ConstraintWrapper(c) for c in self._right_constraints[
                policyrep.ConstraintRuletype.mlsconstrain]))

    def diff_validatetrans(self) -> None:
        """Generate the difference in validatetrans rules between the policies."""

        self.log.info(
            f"Generating validatetrans differences from {self.left_policy} to {self.right_policy}")

        if self._left_constraints is None or self._right_constraints is None:
            self._create_constrain_lists()

        assert self._left_constraints is not None, "Left constraints didn't load, this a bug."
        assert self._right_constraints is not None, "Right constraints didn't load, this a bug."

        self.added_validatetrans, self.removed_validatetrans, _ = self._set_diff(
            (ConstraintWrapper(c) for c in self._left_constraints[
                policyrep.ConstraintRuletype.validatetrans]),
            (ConstraintWrapper(c) for c in self._right_constraints[
                policyrep.ConstraintRuletype.validatetrans]))

    def diff_mlsvalidatetrans(self) -> None:
        """Generate the difference in MLS validatetrans rules between the policies."""

        self.log.info(
            f"Generating mlsvalidatetrans differences from {self.left_policy} "
            f"to {self.right_policy}")

        if self._left_constraints is None or self._right_constraints is None:
            self._create_constrain_lists()

        assert self._left_constraints is not None, "Left constraints didn't load, this a bug."
        assert self._right_constraints is not None, "Right constraints didn't load, this a bug."

        self.added_mlsvalidatetrans, self.removed_mlsvalidatetrans, _ = self._set_diff(
            (ConstraintWrapper(c) for c in self._left_constraints[
                policyrep.ConstraintRuletype.mlsvalidatetrans]),
            (ConstraintWrapper(c) for c in self._right_constraints[
                policyrep.ConstraintRuletype.mlsvalidatetrans]))

    added_constrains = DiffResultDescriptor[policyrep.Constraint](diff_constrains)
    removed_constrains = DiffResultDescriptor[policyrep.Constraint](diff_constrains)

    added_mlsconstrains = DiffResultDescriptor[policyrep.Constraint](diff_mlsconstrains)
    removed_mlsconstrains = DiffResultDescriptor[policyrep.Constraint](diff_mlsconstrains)

    added_validatetrans = DiffResultDescriptor[policyrep.Validatetrans](diff_validatetrans)
    removed_validatetrans = DiffResultDescriptor[policyrep.Validatetrans](diff_validatetrans)

    added_mlsvalidatetrans = DiffResultDescriptor[policyrep.Validatetrans](diff_mlsvalidatetrans)
    removed_mlsvalidatetrans = DiffResultDescriptor[policyrep.Validatetrans](diff_mlsvalidatetrans)

    # Lists of rules for each policy
    _left_constraints: RuleList[policyrep.ConstraintRuletype, policyrep.AnyConstraint] = None
    _right_constraints: RuleList[policyrep.ConstraintRuletype, policyrep.AnyConstraint] = None

    #
    # Internal functions
    #
    def _create_constrain_lists(self) -> None:
        """Create rule lists for both policies."""
        self._left_constraints = defaultdict(list)
        self.log.debug(f"Building constraint lists from {self.left_policy}")
        for rule in self.left_policy.constraints():
            self._left_constraints[rule.ruletype].append(rule)

        for ruletype, rules in self._left_constraints.items():
            self.log.debug(f"Loaded {len(rules)} {ruletype} rules.")

        self._right_constraints = defaultdict(list)
        self.log.debug(f"Building constraint lists from {self.right_policy}")
        for rule in self.right_policy.constraints():
            self._right_constraints[rule.ruletype].append(rule)

        for ruletype, rules in self._right_constraints.items():
            self.log.debug(f"Loaded {len(rules)} {ruletype} rules.")

        self.log.debug("Completed building constraint rule lists.")

    def _reset_diff(self) -> None:
        """Reset diff results on policy changes."""
        self.log.debug("Resetting all constraints differences")
        del self.added_constrains
        del self.removed_constrains
        del self.added_mlsconstrains
        del self.removed_mlsconstrains
        del self.added_validatetrans
        del self.removed_validatetrans
        del self.added_mlsvalidatetrans
        del self.removed_mlsvalidatetrans

        # Sets of rules for each policy
        self._left_constraints = None
        self._right_constraints = None


class ConstraintWrapper(Wrapper[policyrep.AnyConstraint]):

    """Wrap constraints for diff purposes."""

    __slots__ = ("ruletype", "tclass", "perms", "expr")

    def __init__(self, rule: policyrep.AnyConstraint) -> None:
        self.origin = rule
        self.ruletype = rule.ruletype
        self.tclass = class_wrapper_factory(rule.tclass)
        self.perms: frozenset[str] | None

        try:
            self.perms = rule.perms
        except AttributeError:
            # (mls)validatetrans
            self.perms = None

        self.key = hash(rule)

        self.expr: list[frozenset[SymbolWrapper[policyrep.Role |
                                                policyrep.Type |
                                                policyrep.User]] | str] = []

        for op in rule.expression:
            if isinstance(op, frozenset):
                # lists of types/users/roles
                self.expr.append(frozenset(SymbolWrapper(item) for item in op))
            else:
                # strings in the expression such as u1/r1/t1 or "=="
                self.expr.append(op)

    def __hash__(self):
        return self.key

    def __lt__(self, other):
        return self.key < other.key

    def __eq__(self, other):
        return self.ruletype == other.ruletype and \
            self.tclass == other.tclass and \
            self.perms == other.perms and \
            self.expr == other.expr
