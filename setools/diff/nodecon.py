# Copyright 2016, Tresys Technology, LLC
# Copyright 2017, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from dataclasses import dataclass

from ..policyrep import Context, Nodecon

from .context import ContextWrapper
from .descriptors import DiffResultDescriptor
from .difference import Difference, DifferenceResult, Wrapper


@dataclass(frozen=True)
class ModifiedNodecon(DifferenceResult):

    """Difference details for a modified netifcon."""

    rule: Nodecon
    added_context: Context
    removed_context: Context

    def __lt__(self, other) -> bool:
        return self.rule < other.rule


class NodeconsDifference(Difference):

    """Determine the difference in nodecons between two policies."""

    added_nodecons = DiffResultDescriptor("diff_nodecons")
    removed_nodecons = DiffResultDescriptor("diff_nodecons")
    modified_nodecons = DiffResultDescriptor("diff_nodecons")

    def diff_nodecons(self) -> None:
        """Generate the difference in nodecons between the policies."""

        self.log.info("Generating nodecon differences from {0.left_policy} to {0.right_policy}".
                      format(self))

        self.added_nodecons, self.removed_nodecons, matched_nodecons = self._set_diff(
            (NodeconWrapper(n) for n in self.left_policy.nodecons()),
            (NodeconWrapper(n) for n in self.right_policy.nodecons()))

        self.modified_nodecons = []

        for left_nodecon, right_nodecon in matched_nodecons:
            # Criteria for modified nodecons
            # 1. change to context
            if ContextWrapper(left_nodecon.context) != ContextWrapper(right_nodecon.context):
                self.modified_nodecons.append(ModifiedNodecon(left_nodecon,
                                                              right_nodecon.context,
                                                              left_nodecon.context))

    #
    # Internal functions
    #
    def _reset_diff(self) -> None:
        """Reset diff results on policy changes."""
        self.log.debug("Resetting nodecon differences")
        self.added_nodecons = None
        self.removed_nodecons = None
        self.modified_nodecons = None


class NodeconWrapper(Wrapper[Nodecon]):

    """Wrap nodecon statements for diff purposes."""

    __slots__ = ("ip_version", "network")

    def __init__(self, ocon: Nodecon) -> None:
        self.origin = ocon
        self.ip_version = ocon.ip_version
        self.network = ocon.network
        self.key = hash(ocon)

    def __hash__(self):
        return self.key

    def __lt__(self, other):
        return self.origin < other.origin

    def __eq__(self, other):
        return self.ip_version == other.ip_version and \
            self.network == other.network
