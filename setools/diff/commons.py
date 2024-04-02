# Copyright 2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from dataclasses import dataclass

from .descriptors import DiffResultDescriptor
from .difference import Difference, DifferenceResult, SymbolWrapper
from .. import policyrep


@dataclass(frozen=True, order=True)
class ModifiedCommon(DifferenceResult):

    """Difference details for a modified common permission set."""

    common: policyrep.Common
    added_perms: set[str]
    removed_perms: set[str]
    matched_perms: set[str]


class CommonDifference(Difference):

    """
    Determine the difference in common permission sets
    between two policies.
    """

    def diff_commons(self) -> None:
        """Generate the difference in commons between the policies."""

        self.log.info(
            f"Generating common differences from {self.left_policy} to {self.right_policy}")

        self.added_commons, self.removed_commons, matched_commons = self._set_diff(
            (SymbolWrapper(c) for c in self.left_policy.commons()),
            (SymbolWrapper(c) for c in self.right_policy.commons()))

        self.modified_commons = list[ModifiedCommon]()

        for left_common, right_common in matched_commons:
            # Criteria for modified commons
            # 1. change to permissions
            added_perms, removed_perms, matched_perms = self._set_diff(left_common.perms,
                                                                       right_common.perms,
                                                                       unwrap=False)

            if added_perms or removed_perms:
                self.modified_commons.append(ModifiedCommon(left_common,
                                                            added_perms,
                                                            removed_perms,
                                                            matched_perms))

    added_commons = DiffResultDescriptor[policyrep.Common](diff_commons)
    removed_commons = DiffResultDescriptor[policyrep.Common](diff_commons)
    modified_commons = DiffResultDescriptor[ModifiedCommon](diff_commons)

    #
    # Internal functions
    #
    def _reset_diff(self) -> None:
        """Reset diff results on policy changes."""
        self.log.debug("Resetting common differences")
        del self.added_commons
        del self.removed_commons
        del self.modified_commons
