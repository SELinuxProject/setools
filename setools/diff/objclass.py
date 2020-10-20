# Copyright 2015, Tresys Technology, LLC
# Copyright 2018, Chris PeBenito <pebenito@ieee.org>
#
# This file is part of SETools.
#
# SETools is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation, either version 2.1 of
# the License, or (at your option) any later version.
#
# SETools is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with SETools.  If not, see
# <http://www.gnu.org/licenses/>.
#
from collections import defaultdict
from contextlib import suppress
from typing import NamedTuple, Set

from ..exception import NoCommon
from ..policyrep import ObjClass

from .descriptors import DiffResultDescriptor
from .difference import Difference, SymbolWrapper
from .typing import SymbolCache

_class_cache: SymbolCache[ObjClass] = defaultdict(dict)


class ModifiedObjClass(NamedTuple):

    """Difference details for a modified object class."""

    added_perms: Set[str]
    removed_perms: Set[str]
    matched_perms: Set[str]


def class_wrapper_factory(class_: ObjClass) -> SymbolWrapper[ObjClass]:
    """
    Wrap class from the specified policy.

    This caches results to prevent duplicate wrapper
    objects in memory.
    """

    try:
        return _class_cache[class_.policy][class_]
    except KeyError:
        c = SymbolWrapper(class_)
        _class_cache[class_.policy][class_] = c
        return c


class ObjClassDifference(Difference):

    """
    Determine the difference in object classes
    between two policies.
    """

    added_classes = DiffResultDescriptor("diff_classes")
    removed_classes = DiffResultDescriptor("diff_classes")
    modified_classes = DiffResultDescriptor("diff_classes")

    def diff_classes(self) -> None:
        """Generate the difference in object classes between the policies."""

        self.log.info(
            "Generating class differences from {0.left_policy} to {0.right_policy}".format(self))

        self.added_classes, self.removed_classes, matched_classes = self._set_diff(
            (SymbolWrapper(c) for c in self.left_policy.classes()),
            (SymbolWrapper(c) for c in self.right_policy.classes()))

        self.modified_classes = dict()

        for left_class, right_class in matched_classes:
            # Criteria for modified classes
            # 1. change to permissions (inherited common is expanded)

            left_perms = left_class.perms
            with suppress(NoCommon):
                left_perms |= left_class.common.perms

            right_perms = right_class.perms
            with suppress(NoCommon):
                right_perms |= right_class.common.perms

            added_perms, removed_perms, matched_perms = self._set_diff(left_perms,
                                                                       right_perms,
                                                                       unwrap=False)

            if added_perms or removed_perms:
                self.modified_classes[left_class] = ModifiedObjClass(added_perms,
                                                                     removed_perms,
                                                                     matched_perms)

    #
    # Internal functions
    #
    def _reset_diff(self) -> None:
        """Reset diff results on policy changes."""
        self.log.debug("Resetting object class differences")
        self.added_classes = None
        self.removed_classes = None
        self.modified_classes = None
