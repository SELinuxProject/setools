# Copyright 2016, Tresys Technology, LLC
# Copyright 2018, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from collections import defaultdict
from typing import NamedTuple, Set

from ..policyrep import Type, TypeAttribute

from .descriptors import DiffResultDescriptor
from .difference import Difference, SymbolWrapper
from .typing import SymbolCache

_typeattr_cache: SymbolCache[TypeAttribute] = defaultdict(dict)


class ModifiedTypeAttribute(NamedTuple):

    """Difference details for a modified type attribute."""

    added_types: Set[Type]
    removed_types: Set[Type]
    matched_types: Set[Type]


def typeattr_wrapper_factory(attr: TypeAttribute) -> SymbolWrapper[TypeAttribute]:
    """
    Wrap type attributes from the specified policy.

    This caches results to prevent duplicate wrapper
    objects in memory.
    """
    try:
        return _typeattr_cache[attr.policy][attr]
    except KeyError:
        a = SymbolWrapper(attr)
        _typeattr_cache[attr.policy][attr] = a
        return a


class TypeAttributesDifference(Difference):

    """Determine the difference in type attributes between two policies."""

    added_type_attributes = DiffResultDescriptor("diff_type_attributes")
    removed_type_attributes = DiffResultDescriptor("diff_type_attributes")
    modified_type_attributes = DiffResultDescriptor("diff_type_attributes")

    def diff_type_attributes(self) -> None:
        """Generate the difference in type attributes between the policies."""

        self.log.info(
            "Generating type attribute differences from {0.left_policy} to {0.right_policy}".
            format(self))

        self.added_type_attributes, self.removed_type_attributes, matched_attributes = \
            self._set_diff(
                (SymbolWrapper(r) for r in self.left_policy.typeattributes()),
                (SymbolWrapper(r) for r in self.right_policy.typeattributes()))

        self.modified_type_attributes = dict()

        for left_attribute, right_attribute in matched_attributes:
            # Criteria for modified attributes
            # 1. change to type set
            added_types, removed_types, matched_types = self._set_diff(
                (SymbolWrapper(t) for t in left_attribute.expand()),
                (SymbolWrapper(t) for t in right_attribute.expand()))

            if added_types or removed_types:
                self.modified_type_attributes[left_attribute] = ModifiedTypeAttribute(
                    added_types, removed_types, matched_types)

    #
    # Internal functions
    #
    def _reset_diff(self) -> None:
        """Reset diff results on policy changes."""
        self.log.debug("Resetting type attribute differences")
        self.added_type_attributes = None
        self.removed_type_attributes = None
        self.modified_type_attributes = None
