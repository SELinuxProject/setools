# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from dataclasses import dataclass

from ..policyrep import PolicyEnum

from .descriptors import DiffResultDescriptor
from .difference import Difference, DifferenceResult


@dataclass(frozen=True)
class ModifiedProperty(DifferenceResult):

    """Difference details for a modified policy property."""

    property: str
    added: PolicyEnum | bool | int
    removed: PolicyEnum | bool | int

    def __lt__(self, other) -> bool:
        return self.property < other.property


class PropertiesDifference(Difference):

    """
    Determine the difference in policy properties
    (unknown permissions, MLS, etc.) between two policies.
    """

    def diff_properties(self) -> None:
        self.modified_properties = list[ModifiedProperty]()

        if self.left_policy.handle_unknown != self.right_policy.handle_unknown:
            self.modified_properties.append(
                ModifiedProperty("handle_unknown",
                                 self.right_policy.handle_unknown,
                                 self.left_policy.handle_unknown))

        if self.left_policy.mls != self.right_policy.mls:
            self.modified_properties.append(
                ModifiedProperty("MLS",
                                 self.right_policy.mls,
                                 self.left_policy.mls))

        if self.left_policy.version != self.right_policy.version:
            self.modified_properties.append(
                ModifiedProperty("version",
                                 self.right_policy.version,
                                 self.left_policy.version))

    modified_properties = DiffResultDescriptor[ModifiedProperty](diff_properties)

    #
    # Internal functions
    #
    def _reset_diff(self) -> None:
        """Reset diff results on policy changes."""
        self.log.debug("Resetting property differences")
        del self.modified_properties
