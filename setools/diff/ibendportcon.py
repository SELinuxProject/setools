# Copyright 2018, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from dataclasses import dataclass

from ..policyrep import Context, Ibendportcon

from .context import ContextWrapper
from .descriptors import DiffResultDescriptor
from .difference import Difference, DifferenceResult, Wrapper


@dataclass(frozen=True)
class ModifiedIbendportcon(DifferenceResult):

    """Difference details for a modified ibendportcon."""

    rule: Ibendportcon
    added_context: Context
    removed_context: Context

    def __lt__(self, other) -> bool:
        return self.rule < other.rule


class IbendportconsDifference(Difference):

    """Determine the difference in ibendportcons between two policies."""

    added_ibendportcons = DiffResultDescriptor("diff_ibendportcons")
    removed_ibendportcons = DiffResultDescriptor("diff_ibendportcons")
    modified_ibendportcons = DiffResultDescriptor("diff_ibendportcons")

    def diff_ibendportcons(self) -> None:
        """Generate the difference in ibendportcons between the policies."""

        self.log.info(
            "Generating ibendportcon differences from {0.left_policy} to {0.right_policy}".
            format(self))

        self.added_ibendportcons, self.removed_ibendportcons, matched_ibendportcons = \
            self._set_diff(
                (IbendportconWrapper(n) for n in self.left_policy.ibendportcons()),
                (IbendportconWrapper(n) for n in self.right_policy.ibendportcons()))

        self.modified_ibendportcons = []

        for left_ibep, right_ibep in matched_ibendportcons:
            # Criteria for modified ibendportcons
            # 1. change to context
            if ContextWrapper(left_ibep.context) != ContextWrapper(right_ibep.context):
                self.modified_ibendportcons.append(
                    ModifiedIbendportcon(left_ibep, right_ibep.context, left_ibep.context))

    #
    # Internal functions
    #
    def _reset_diff(self) -> None:
        """Reset diff results on policy changes."""
        self.log.debug("Resetting ibendportcon differences")
        self.added_ibendportcons = None
        self.removed_ibendportcons = None
        self.modified_ibendportcons = None


class IbendportconWrapper(Wrapper[Ibendportcon]):

    """Wrap ibendportcon statements for diff purposes."""

    __slots__ = ("name", "port")

    def __init__(self, ocon: Ibendportcon) -> None:
        self.origin = ocon
        self.name = ocon.name
        self.port = ocon.port
        self.key = hash(ocon)

    def __hash__(self):
        return self.key

    def __lt__(self, other):
        return self.origin < other.origin

    def __eq__(self, other):
        return self.name == other.name and \
            self.port == other.port
