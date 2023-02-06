# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from typing import NamedTuple

from ..policyrep import Context, Portcon

from .context import ContextWrapper
from .descriptors import DiffResultDescriptor
from .difference import Difference, Wrapper


class ModifiedPortcon(NamedTuple):

    """Difference details for a modified portcon."""

    rule: Portcon
    added_context: Context
    removed_context: Context


class PortconsDifference(Difference):

    """Determine the difference in portcons between two policies."""

    added_portcons = DiffResultDescriptor("diff_portcons")
    removed_portcons = DiffResultDescriptor("diff_portcons")
    modified_portcons = DiffResultDescriptor("diff_portcons")

    def diff_portcons(self) -> None:
        """Generate the difference in portcons between the policies."""

        self.log.info("Generating portcon differences from {0.left_policy} to {0.right_policy}".
                      format(self))

        self.added_portcons, self.removed_portcons, matched_portcons = self._set_diff(
            (PortconWrapper(n) for n in self.left_policy.portcons()),
            (PortconWrapper(n) for n in self.right_policy.portcons()))

        self.modified_portcons = []

        for left_portcon, right_portcon in matched_portcons:
            # Criteria for modified portcons
            # 1. change to context
            if ContextWrapper(left_portcon.context) != ContextWrapper(right_portcon.context):
                self.modified_portcons.append(ModifiedPortcon(left_portcon,
                                                              right_portcon.context,
                                                              left_portcon.context))

    #
    # Internal functions
    #
    def _reset_diff(self) -> None:
        """Reset diff results on policy changes."""
        self.log.debug("Resetting portcon differences")
        self.added_portcons = None
        self.removed_portcons = None
        self.modified_portcons = None


class PortconWrapper(Wrapper[Portcon]):

    """Wrap portcon statements for diff purposes."""

    __slots__ = ("protocol", "low", "high")

    def __init__(self, ocon: Portcon) -> None:
        self.origin = ocon
        self.protocol = ocon.protocol
        self.low, self.high = ocon.ports
        self.key = hash(ocon)

    def __hash__(self):
        return self.key

    def __lt__(self, other):
        return self.origin < other.origin

    def __eq__(self, other):
        return self.protocol == other.protocol and \
            self.low == other.low and \
            self.high == other.high
