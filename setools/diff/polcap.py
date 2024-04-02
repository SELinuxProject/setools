# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from .descriptors import DiffResultDescriptor
from .difference import Difference, SymbolWrapper

from .. import policyrep


class PolCapsDifference(Difference):

    """Determine the difference in polcaps between two policies."""

    def diff_polcaps(self) -> None:
        """Generate the difference in polcaps between the policies."""

        self.log.info(
            f"Generating policy cap differences from {self.left_policy} to {self.right_policy}")

        self.added_polcaps, self.removed_polcaps, _ = self._set_diff(
            (SymbolWrapper(n) for n in self.left_policy.polcaps()),
            (SymbolWrapper(n) for n in self.right_policy.polcaps()))

    added_polcaps = DiffResultDescriptor[policyrep.PolicyCapability](diff_polcaps)
    removed_polcaps = DiffResultDescriptor[policyrep.PolicyCapability](diff_polcaps)

    #
    # Internal functions
    #
    def _reset_diff(self) -> None:
        """Reset diff results on policy changes."""
        self.log.debug("Resetting policy capability differences")
        del self.added_polcaps
        del self.removed_polcaps
