# Copyright 2016, Tresys Technology, LLC
# Copyright 2018, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from collections import defaultdict
from dataclasses import dataclass

from ..policyrep import SELinuxPolicy, Boolean

from .descriptors import DiffResultDescriptor
from .difference import Difference, DifferenceResult, SymbolWrapper
from .typing import SymbolCache


_bool_cache: SymbolCache[Boolean] = defaultdict(dict)


@dataclass(frozen=True, order=True)
class ModifiedBoolean(DifferenceResult):

    """Difference details for a modified Boolean."""

    boolean: Boolean
    added_state: bool
    removed_state: bool


def boolean_wrapper(policy: SELinuxPolicy, boolean: Boolean) -> SymbolWrapper[Boolean]:
    """
    Wrap booleans from the specified policy.

    This caches results to prevent duplicate wrapper
    objects in memory.
    """
    try:
        return _bool_cache[policy][boolean]
    except KeyError:
        b = SymbolWrapper(boolean)
        _bool_cache[policy][boolean] = b
        return b


class BooleansDifference(Difference):

    """Determine the difference in type attributes between two policies."""

    def diff_booleans(self) -> None:
        """Generate the difference in type attributes between the policies."""

        self.log.info(
            f"Generating Boolean differences from {self.left_policy} to {self.right_policy}")

        self.added_booleans, self.removed_booleans, matched_booleans = \
            self._set_diff(
                (SymbolWrapper(b) for b in self.left_policy.bools()),
                (SymbolWrapper(b) for b in self.right_policy.bools()))

        self.modified_booleans = list[ModifiedBoolean]()

        for left_boolean, right_boolean in matched_booleans:
            # Criteria for modified booleans
            # 1. change to default state
            if left_boolean.state != right_boolean.state:
                self.modified_booleans.append(ModifiedBoolean(left_boolean,
                                                              right_boolean.state,
                                                              left_boolean.state))

    added_booleans = DiffResultDescriptor[Boolean](diff_booleans)
    removed_booleans = DiffResultDescriptor[Boolean](diff_booleans)
    modified_booleans = DiffResultDescriptor[ModifiedBoolean](diff_booleans)

    #
    # Internal functions
    #
    def _reset_diff(self) -> None:
        """Reset diff results on policy changes."""
        self.log.debug("Resetting Boolean differences")
        del self.added_booleans
        del self.removed_booleans
        del self.modified_booleans
