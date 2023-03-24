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

    added_booleans = DiffResultDescriptor("diff_booleans")
    removed_booleans = DiffResultDescriptor("diff_booleans")
    modified_booleans = DiffResultDescriptor("diff_booleans")

    def diff_booleans(self) -> None:
        """Generate the difference in type attributes between the policies."""

        self.log.info("Generating Boolean differences from {0.left_policy} to {0.right_policy}".
                      format(self))

        self.added_booleans, self.removed_booleans, matched_booleans = \
            self._set_diff(
                (SymbolWrapper(b) for b in self.left_policy.bools()),
                (SymbolWrapper(b) for b in self.right_policy.bools()))

        self.modified_booleans = dict()

        for left_boolean, right_boolean in matched_booleans:
            # Criteria for modified booleans
            # 1. change to default state
            if left_boolean.state != right_boolean.state:
                self.modified_booleans[left_boolean] = ModifiedBoolean(right_boolean.state,
                                                                       left_boolean.state)

    #
    # Internal functions
    #
    def _reset_diff(self) -> None:
        """Reset diff results on policy changes."""
        self.log.debug("Resetting Boolean differences")
        self.added_booleans = None
        self.removed_booleans = None
        self.modified_booleans = None
