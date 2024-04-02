# Copyright 2015, Tresys Technology, LLC
# Copyright 2018, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from collections import defaultdict
from dataclasses import dataclass

from ..policyrep import Type, TypeAttribute, TypeOrAttr

from .descriptors import DiffResultDescriptor
from .difference import Difference, DifferenceResult, SymbolWrapper
from .typeattr import typeattr_wrapper_factory
from .typing import SymbolCache

_types_cache: SymbolCache[Type] = defaultdict(dict)


@dataclass(frozen=True, order=True)
class ModifiedType(DifferenceResult):

    """Difference details for a modified type."""

    type_: Type
    added_attributes: set[TypeAttribute]
    removed_attributes: set[TypeAttribute]
    matched_attributes: set[TypeAttribute]
    modified_permissive: bool
    permissive: bool
    added_aliases: set[str]
    removed_aliases: set[str]
    matched_aliases: set[str]


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
        SymbolWrapper[Type] | SymbolWrapper[TypeAttribute]:

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

    def diff_types(self) -> None:
        """Generate the difference in types between the policies."""

        self.log.info(
            f"Generating type differences from {self.left_policy} to {self.right_policy}")

        self.added_types, self.removed_types, matched_types = self._set_diff(
            (SymbolWrapper(t) for t in self.left_policy.types()),
            (SymbolWrapper(t) for t in self.right_policy.types()))

        self.modified_types = list[ModifiedType]()

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
                self.modified_types.append(ModifiedType(left_type,
                                                        added_attr,
                                                        removed_attr,
                                                        matched_attr,
                                                        mod_permissive,
                                                        left_permissive,
                                                        added_aliases,
                                                        removed_aliases,
                                                        matched_aliases))

    added_types = DiffResultDescriptor[Type](diff_types)
    removed_types = DiffResultDescriptor[Type](diff_types)
    modified_types = DiffResultDescriptor[ModifiedType](diff_types)

    #
    # Internal functions
    #
    def _reset_diff(self) -> None:
        """Reset diff results on policy changes."""
        self.log.debug("Resetting type differences")
        del self.added_types
        del self.removed_types
        del self.modified_types
