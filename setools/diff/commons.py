# Copyright 2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from dataclasses import dataclass
from typing import Set

from .descriptors import DiffResultDescriptor
from .difference import Difference, DifferenceResult, SymbolWrapper


@dataclass(frozen=True, order=True)
class ModifiedCommon(DifferenceResult):

    """Difference details for a modified common permission set."""

    added_perms: Set[str]
    removed_perms: Set[str]
    matched_perms: Set[str]


class CommonDifference(Difference):

    """
    Determine the difference in common permission sets
    between two policies.
    """

    added_commons = DiffResultDescriptor("diff_commons")
    removed_commons = DiffResultDescriptor("diff_commons")
    modified_commons = DiffResultDescriptor("diff_commons")

    def diff_commons(self) -> None:
        """Generate the difference in commons between the policies."""

        self.log.info(
            "Generating common differences from {0.left_policy} to {0.right_policy}".format(self))

        self.added_commons, self.removed_commons, matched_commons = self._set_diff(
            (SymbolWrapper(c) for c in self.left_policy.commons()),
            (SymbolWrapper(c) for c in self.right_policy.commons()))

        self.modified_commons = dict()

        for left_common, right_common in matched_commons:
            # Criteria for modified commons
            # 1. change to permissions
            added_perms, removed_perms, matched_perms = self._set_diff(left_common.perms,
                                                                       right_common.perms,
                                                                       unwrap=False)

            if added_perms or removed_perms:
                self.modified_commons[left_common] = ModifiedCommon(added_perms,
                                                                    removed_perms,
                                                                    matched_perms)

    #
    # Internal functions
    #
    def _reset_diff(self) -> None:
        """Reset diff results on policy changes."""
        self.log.debug("Resetting common differences")
        self.added_commons = None
        self.removed_commons = None
        self.modified_commons = None
