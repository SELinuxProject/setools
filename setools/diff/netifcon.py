# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from dataclasses import dataclass

from ..policyrep import Context, Netifcon

from .context import ContextWrapper
from .descriptors import DiffResultDescriptor
from .difference import Difference, DifferenceResult, Wrapper


@dataclass(frozen=True, order=True)
class ModifiedNetifcon(DifferenceResult):

    """Difference details for a modified netifcon."""

    rule: Netifcon
    added_context: Context | None
    removed_context: Context | None
    added_packet: Context | None
    removed_packet: Context | None


class NetifconsDifference(Difference):

    """Determine the difference in netifcons between two policies."""

    def diff_netifcons(self) -> None:
        """Generate the difference in netifcons between the policies."""

        self.log.info(
            f"Generating netifcon differences from {self.left_policy} to {self.right_policy}")

        self.added_netifcons, self.removed_netifcons, matched_netifcons = self._set_diff(
            (NetifconWrapper(n) for n in self.left_policy.netifcons()),
            (NetifconWrapper(n) for n in self.right_policy.netifcons()))

        self.modified_netifcons = list[ModifiedNetifcon]()

        for left_netifcon, right_netifcon in matched_netifcons:
            # Criteria for modified netifcons
            # 1. change to context
            # 2. change to packet context
            if ContextWrapper(left_netifcon.context) != ContextWrapper(right_netifcon.context):
                removed_context = left_netifcon.context
                added_context = right_netifcon.context
            else:
                removed_context = None
                added_context = None

            if ContextWrapper(left_netifcon.packet) != ContextWrapper(right_netifcon.packet):
                removed_packet = left_netifcon.packet
                added_packet = right_netifcon.packet
            else:
                removed_packet = None
                added_packet = None

            if removed_context or removed_packet:
                self.modified_netifcons.append(ModifiedNetifcon(
                    left_netifcon, added_context, removed_context, added_packet, removed_packet))

    added_netifcons = DiffResultDescriptor[Netifcon](diff_netifcons)
    removed_netifcons = DiffResultDescriptor[Netifcon](diff_netifcons)
    modified_netifcons = DiffResultDescriptor[ModifiedNetifcon](diff_netifcons)

    #
    # Internal functions
    #
    def _reset_diff(self) -> None:
        """Reset diff results on policy changes."""
        self.log.debug("Resetting netifcon differences")
        del self.added_netifcons
        del self.removed_netifcons
        del self.modified_netifcons


class NetifconWrapper(Wrapper[Netifcon]):

    """Wrap netifcon statements for diff purposes."""

    __slots__ = ("netif")

    def __init__(self, ocon: Netifcon) -> None:
        self.origin = ocon
        self.netif = ocon.netif
        self.key = hash(ocon)

    def __hash__(self):
        return self.key

    def __lt__(self, other):
        return self.netif < other.netif

    def __eq__(self, other):
        return self.netif == other.netif
