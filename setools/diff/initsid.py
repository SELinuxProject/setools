# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from dataclasses import dataclass

from ..policyrep import Context

from .context import ContextWrapper
from .descriptors import DiffResultDescriptor
from .difference import Difference, DifferenceResult, SymbolWrapper


@dataclass(frozen=True, order=True)
class ModifiedInitialSID(DifferenceResult):

    """Difference details for a modified initial SID."""

    added_context: Context
    removed_context: Context


class InitialSIDsDifference(Difference):

    """Determine the difference in initsids between two policies."""

    added_initialsids = DiffResultDescriptor("diff_initialsids")
    removed_initialsids = DiffResultDescriptor("diff_initialsids")
    modified_initialsids = DiffResultDescriptor("diff_initialsids")

    def diff_initialsids(self) -> None:
        """Generate the difference in initial SIDs between the policies."""

        self.log.info("Generating initial SID differences from {0.left_policy} to {0.right_policy}".
                      format(self))

        self.added_initialsids, self.removed_initialsids, matched_initialsids = self._set_diff(
            (SymbolWrapper(i) for i in self.left_policy.initialsids()),
            (SymbolWrapper(i) for i in self.right_policy.initialsids()))

        self.modified_initialsids = dict()

        for left_initialsid, right_initialsid in matched_initialsids:
            # Criteria for modified initialsids
            # 1. change to context
            if ContextWrapper(left_initialsid.context) != ContextWrapper(right_initialsid.context):
                self.modified_initialsids[left_initialsid] = ModifiedInitialSID(
                    right_initialsid.context, left_initialsid.context)

    #
    # Internal functions
    #
    def _reset_diff(self) -> None:
        """Reset diff results on policy changes."""
        self.log.debug("Resetting initialsid differences")
        self.added_initialsids = None
        self.removed_initialsids = None
        self.modified_initialsids = None
