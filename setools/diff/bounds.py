# Copyright 2016, Tresys Technology, LLC
# Copyright 2018, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from dataclasses import dataclass
import typing

from ..policyrep import Bounds, BoundsRuletype, Type

from .descriptors import DiffResultDescriptor
from .difference import Difference, DifferenceResult, Wrapper
from .types import type_wrapper_factory


@dataclass(frozen=True, order=True)
class ModifiedBounds(DifferenceResult):

    """Difference details for a modified bounds rule."""

    rule: Bounds
    added_bound: Type
    removed_bound: Type


class BoundsDifference(Difference):

    """Determine the difference in *bounds between two policies."""

    def diff_typebounds(self) -> None:
        """Generate the difference in typebound rules between the policies."""

        self.log.info(
            f"Generating typebounds differences from {self.left_policy} to {self.right_policy}")

        if self._left_typebounds is None or self._right_typebounds is None:
            self._create_typebound_lists()

        self.added_typebounds, self.removed_typebounds, matched_typebounds = self._set_diff(
            (BoundsWrapper(c) for c in typing.cast(list[Bounds], self._left_typebounds)),
            (BoundsWrapper(c) for c in typing.cast(list[Bounds], self._right_typebounds)),
            key=lambda b: str(b.child))

        self.modified_typebounds = list[ModifiedBounds]()

        for left_bound, right_bound in matched_typebounds:
            if type_wrapper_factory(left_bound.parent) != type_wrapper_factory(right_bound.parent):
                self.modified_typebounds.append(ModifiedBounds(
                    left_bound, right_bound.parent, left_bound.parent))

    added_typebounds = DiffResultDescriptor[Bounds](diff_typebounds)
    removed_typebounds = DiffResultDescriptor[Bounds](diff_typebounds)
    modified_typebounds = DiffResultDescriptor[ModifiedBounds](diff_typebounds)

    # Lists of rules for each policy
    _left_typebounds: list[Bounds] | None = None
    _right_typebounds: list[Bounds] | None = None

    #
    # Internal functions
    #
    def _create_typebound_lists(self) -> None:
        """Create rule lists for both policies."""
        self._left_typebounds = []
        for rule in self.left_policy.bounds():
            if rule.ruletype == BoundsRuletype.typebounds:
                self._left_typebounds.append(rule)
            else:
                self.log.error(f"Unknown rule type: {rule.ruletype} (This is an SETools bug)")

        self._right_typebounds = []
        for rule in self.right_policy.bounds():
            if rule.ruletype == BoundsRuletype.typebounds:
                self._right_typebounds.append(rule)
            else:
                self.log.error(f"Unknown rule type: {rule.ruletype} (This is an SETools bug)")

    def _reset_diff(self) -> None:
        """Reset diff results on policy changes."""
        self.log.debug("Resetting all *bounds differences")
        del self.added_typebounds
        del self.removed_typebounds

        # Sets of rules for each policy
        self._left_typebounds = None
        self._right_typebounds = None


class BoundsWrapper(Wrapper[Bounds]):

    """Wrap *bounds for diff purposes."""

    __slots__ = ("ruletype", "parent", "child")

    def __init__(self, rule: Bounds) -> None:
        self.origin = rule
        self.ruletype = rule.ruletype
        self.parent = type_wrapper_factory(rule.parent)
        self.child = type_wrapper_factory(rule.child)
        self.key = hash(rule)

    def __hash__(self):
        return self.key

    def __lt__(self, other):
        return self.key < other.key

    def __eq__(self, other):
        return self.ruletype == other.ruletype and \
            self.child == other.child
