# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from dataclasses import dataclass

from .. import policyrep

from .context import ContextWrapper
from .descriptors import DiffResultDescriptor
from .difference import Difference, DifferenceResult, SymbolWrapper


@dataclass(frozen=True, order=True)
class ModifiedInitialSID(DifferenceResult):

    """Difference details for a modified initial SID."""

    isid: policyrep.InitialSID
    added_context: policyrep.Context
    removed_context: policyrep.Context


class InitialSIDsDifference(Difference):

    """Determine the difference in initsids between two policies."""

    def diff_initialsids(self) -> None:
        """Generate the difference in initial SIDs between the policies."""

        self.log.info(
            f"Generating initial SID differences from {self.left_policy} to {self.right_policy}")

        self.added_initialsids, self.removed_initialsids, matched_initialsids = self._set_diff(
            (SymbolWrapper(i) for i in self.left_policy.initialsids()),
            (SymbolWrapper(i) for i in self.right_policy.initialsids()))

        self.modified_initialsids = list[ModifiedInitialSID]()

        for left_initialsid, right_initialsid in matched_initialsids:
            # Criteria for modified initialsids
            # 1. change to context
            if ContextWrapper(left_initialsid.context) != ContextWrapper(right_initialsid.context):
                self.modified_initialsids.append(ModifiedInitialSID(
                    left_initialsid, right_initialsid.context, left_initialsid.context))

    added_initialsids = DiffResultDescriptor[policyrep.InitialSID](diff_initialsids)
    removed_initialsids = DiffResultDescriptor[policyrep.InitialSID](diff_initialsids)
    modified_initialsids = DiffResultDescriptor[ModifiedInitialSID](diff_initialsids)

    #
    # Internal functions
    #
    def _reset_diff(self) -> None:
        """Reset diff results on policy changes."""
        self.log.debug("Resetting initialsid differences")
        del self.added_initialsids
        del self.removed_initialsids
        del self.modified_initialsids
