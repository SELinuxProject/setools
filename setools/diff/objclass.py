# Copyright 2015, Tresys Technology, LLC
# Copyright 2018, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from collections import defaultdict
from contextlib import suppress
from dataclasses import dataclass

from ..exception import NoCommon
from ..policyrep import ObjClass

from .descriptors import DiffResultDescriptor
from .difference import Difference, DifferenceResult, SymbolWrapper
from .typing import SymbolCache

_class_cache: SymbolCache[ObjClass] = defaultdict(dict)


@dataclass(frozen=True, order=True)
class ModifiedObjClass(DifferenceResult):

    """Difference details for a modified object class."""

    class_: ObjClass
    added_perms: set[str]
    removed_perms: set[str]
    matched_perms: set[str]


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

    def diff_classes(self) -> None:
        """Generate the difference in object classes between the policies."""

        self.log.info(
            f"Generating class differences from {self.left_policy} to {self.right_policy}")

        self.added_classes, self.removed_classes, matched_classes = self._set_diff(
            (SymbolWrapper(c) for c in self.left_policy.classes()),
            (SymbolWrapper(c) for c in self.right_policy.classes()))

        self.modified_classes = list[ModifiedObjClass]()

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
                self.modified_classes.append(ModifiedObjClass(left_class,
                                                              added_perms,
                                                              removed_perms,
                                                              matched_perms))

    added_classes = DiffResultDescriptor[ObjClass](diff_classes)
    removed_classes = DiffResultDescriptor[ObjClass](diff_classes)
    modified_classes = DiffResultDescriptor[ModifiedObjClass](diff_classes)

    #
    # Internal functions
    #
    def _reset_diff(self) -> None:
        """Reset diff results on policy changes."""
        self.log.debug("Resetting object class differences")
        del self.added_classes
        del self.removed_classes
        del self.modified_classes
