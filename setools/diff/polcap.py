# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from .descriptors import DiffResultDescriptor
from .difference import Difference, SymbolWrapper


class PolCapsDifference(Difference):

    """Determine the difference in polcaps between two policies."""

    added_polcaps = DiffResultDescriptor("diff_polcaps")
    removed_polcaps = DiffResultDescriptor("diff_polcaps")

    def diff_polcaps(self) -> None:
        """Generate the difference in polcaps between the policies."""

        self.log.info("Generating policy cap differences from {0.left_policy} to {0.right_policy}".
                      format(self))

        self.added_polcaps, self.removed_polcaps, _ = self._set_diff(
            (SymbolWrapper(n) for n in self.left_policy.polcaps()),
            (SymbolWrapper(n) for n in self.right_policy.polcaps()))

    #
    # Internal functions
    #
    def _reset_diff(self) -> None:
        """Reset diff results on policy changes."""
        self.log.debug("Resetting policy capability differences")
        self.added_polcaps = None
        self.removed_polcaps = None
