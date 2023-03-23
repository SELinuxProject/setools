# Copyright 2015, Tresys Technology, LLC
# Copyright 2018, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from collections import defaultdict
from dataclasses import dataclass
from typing import Set, Union

from ..policyrep import Type, TypeAttribute, TypeOrAttr

from .descriptors import DiffResultDescriptor
from .difference import Difference, DifferenceResult, SymbolWrapper
from .typeattr import typeattr_wrapper_factory
from .typing import SymbolCache

_types_cache: SymbolCache[Type] = defaultdict(dict)


@dataclass(frozen=True, order=True)
class ModifiedType(DifferenceResult):

    """Difference details for a modified type."""

    added_attributes: Set[TypeAttribute]
    removed_attributes: Set[TypeAttribute]
    matched_attributes: Set[TypeAttribute]
    modified_permissive: bool
    permissive: bool
    added_aliases: Set[str]
    removed_aliases: Set[str]
    matched_aliases: Set[str]


def type_wrapper_factory(type_: Type) -> SymbolWrapper[Type]:
    """
    Wrap types from the specified policy.

    This caches results to prevent duplicate wrapper
    objects in memory.
    """
    try:
        return _types_cache[type_.policy][type_]
    except KeyError:
        t = SymbolWrapper(type_)
        _types_cache[type_.policy][type_] = t
        return t


def type_or_attr_wrapper_factory(type_: TypeOrAttr) -> \
        Union[SymbolWrapper[Type], SymbolWrapper[TypeAttribute]]:

    """
    Wrap types or attributes from the specified policy.

    This caches results to prevent duplicate wrapper
    objects in memory.
    """
    if isinstance(type_, Type):
        return type_wrapper_factory(type_)
    else:
        return typeattr_wrapper_factory(type_)


class TypesDifference(Difference):

    """Determine the difference in types between two policies."""

    added_types = DiffResultDescriptor("diff_types")
    removed_types = DiffResultDescriptor("diff_types")
    modified_types = DiffResultDescriptor("diff_types")

    def diff_types(self) -> None:
        """Generate the difference in types between the policies."""

        self.log.info(
            "Generating type differences from {0.left_policy} to {0.right_policy}".format(self))

        self.added_types, self.removed_types, matched_types = self._set_diff(
            (SymbolWrapper(t) for t in self.left_policy.types()),
            (SymbolWrapper(t) for t in self.right_policy.types()))

        self.modified_types = dict()

        for left_type, right_type in matched_types:
            # Criteria for modified types
            # 1. change to attribute set, or
            # 2. change to alias set, or
            # 3. different permissive setting
            added_attr, removed_attr, matched_attr = self._set_diff(
                (SymbolWrapper(a) for a in left_type.attributes()),
                (SymbolWrapper(a) for a in right_type.attributes()))

            added_aliases, removed_aliases, matched_aliases = self._set_diff(left_type.aliases(),
                                                                             right_type.aliases(),
                                                                             unwrap=False)

            left_permissive = left_type.ispermissive
            right_permissive = right_type.ispermissive
            mod_permissive = left_permissive != right_permissive

            if added_attr or removed_attr or added_aliases or removed_aliases or mod_permissive:
                self.modified_types[left_type] = ModifiedType(added_attr,
                                                              removed_attr,
                                                              matched_attr,
                                                              mod_permissive,
                                                              left_permissive,
                                                              added_aliases,
                                                              removed_aliases,
                                                              matched_aliases)

    #
    # Internal functions
    #
    def _reset_diff(self) -> None:
        """Reset diff results on policy changes."""
        self.log.debug("Resetting type differences")
        self.added_types = None
        self.removed_types = None
        self.modified_types = None
