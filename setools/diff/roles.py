# Copyright 2015, Tresys Technology, LLC
# Copyright 2018, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from collections import defaultdict
from dataclasses import dataclass
from typing import Set

from ..policyrep import Role, Type

from .descriptors import DiffResultDescriptor
from .difference import Difference, DifferenceResult, SymbolWrapper
from .typing import SymbolCache
from .types import type_wrapper_factory

_roles_cache: SymbolCache[Role] = defaultdict(dict)


@dataclass(frozen=True, order=True)
class ModifiedRole(DifferenceResult):

    """Difference details for a modified role."""

    added_types: Set[Type]
    removed_types: Set[Type]
    matched_types: Set[Type]


def role_wrapper_factory(role: Role) -> SymbolWrapper[Role]:
    """
    Wrap roles from the specified policy.

    This caches results to prevent duplicate wrapper
    objects in memory.
    """
    try:
        return _roles_cache[role.policy][role]
    except KeyError:
        r = SymbolWrapper(role)
        _roles_cache[role.policy][role] = r
        return r


class RolesDifference(Difference):

    """Determine the difference in roles between two policies."""

    added_roles = DiffResultDescriptor("diff_roles")
    removed_roles = DiffResultDescriptor("diff_roles")
    modified_roles = DiffResultDescriptor("diff_roles")

    def diff_roles(self) -> None:
        """Generate the difference in roles between the policies."""

        self.log.info(
            "Generating role differences from {0.left_policy} to {0.right_policy}".format(self))

        self.added_roles, self.removed_roles, matched_roles = self._set_diff(
            (role_wrapper_factory(r) for r in self.left_policy.roles()),
            (role_wrapper_factory(r) for r in self.right_policy.roles()))

        self.modified_roles = dict()

        for left_role, right_role in matched_roles:
            # Criteria for modified roles
            # 1. change to type set, or
            # 2. change to attribute set (not implemented)
            added_types, removed_types, matched_types = self._set_diff(
                (type_wrapper_factory(t) for t in left_role.types()),
                (type_wrapper_factory(t) for t in right_role.types()))

            if added_types or removed_types:
                self.modified_roles[left_role] = ModifiedRole(added_types,
                                                              removed_types,
                                                              matched_types)

    #
    # Internal functions
    #
    def _reset_diff(self) -> None:
        """Reset diff results on policy changes."""
        self.log.debug("Resetting role differences")
        self.added_roles = None
        self.removed_roles = None
        self.modified_roles = None
