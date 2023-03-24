# Copyright 2015, Tresys Technology, LLC
# Copyright 2019, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: LGPL-2.1-only
#
# pylint: disable=attribute-defined-outside-init,no-member
from dataclasses import astuple
from logging import Logger
from typing import Any
import warnings

from .descriptors import CriteriaDescriptor, CriteriaSetDescriptor, CriteriaPermissionSetDescriptor
from .policyrep import Context
from .util import match_in_set, match_regex, match_range, match_regex_or_set


class MatchAlias:

    """Mixin for matching an object's aliases."""

    alias = CriteriaDescriptor("alias_regex")
    alias_regex: bool = False

    def _match_alias_debug(self, log: Logger) -> None:
        """Emit log debugging info for alias matching."""
        log.debug("Alias: {0.alias}, regex: {0.alias_regex}".format(self))

    def _match_alias(self, obj):
        """
        Match the alias criteria

        Parameter:
        obj     An object with an alias generator method named "aliases"
        """

        if not self.alias:
            # if there is no criteria, everything matches.
            return True

        return match_in_set(obj.aliases(), self.alias, self.alias_regex)


class MatchContext:

    """
    Mixin for matching contexts.

    Class attributes:
    user            The user to match in the context.
    user_regex      If true, regular expression matching
                    will be used on the user.
    role            The role to match in the context.
    role_regex      If true, regular expression matching
                    will be used on the role.
    type_           The type to match in the context.
    type_regex      If true, regular expression matching
                    will be used on the type.
    range_          The range to match in the context.
    range_subset    If true, the criteria will match if it
                    is a subset of the context's range.
    range_overlap   If true, the criteria will match if it
                    overlaps any of the context's range.
    range_superset  If true, the criteria will match if it
                    is a superset of the context's range.
    range_proper    If true, use proper superset/subset
                    on range matching operations.
                    No effect if not using set operations.
    """

    user = CriteriaDescriptor("user_regex", "lookup_user")
    user_regex: bool = False
    role = CriteriaDescriptor("role_regex", "lookup_role")
    role_regex: bool = False
    type_ = CriteriaDescriptor("type_regex", "lookup_type")
    type_regex: bool = False
    range_ = CriteriaDescriptor(lookup_function="lookup_range")
    range_overlap: bool = False
    range_subset: bool = False
    range_superset: bool = False
    range_proper: bool = False

    def _match_context_debug(self, log: Logger):
        """Emit log debugging info for context matching."""
        log.debug("User: {0.user!r}, regex: {0.user_regex}".format(self))
        log.debug("Role: {0.role!r}, regex: {0.role_regex}".format(self))
        log.debug("Type: {0.type_!r}, regex: {0.type_regex}".format(self))
        log.debug("Range: {0.range_!r}, subset: {0.range_subset}, overlap: {0.range_overlap}, "
                  "superset: {0.range_superset}, proper: {0.range_proper}".format(self))

    def _match_context(self, context: Context) -> bool:
        """
        Match the context criteria.

        Parameter:
        obj     An object with context attributes "user", "role",
                "type_" and "range_".
        """

        if self.user and not match_regex(
                context.user,
                self.user,
                self.user_regex):
            return False

        if self.role and not match_regex(
                context.role,
                self.role,
                self.role_regex):
            return False

        if self.type_ and not match_regex(
                context.type_,
                self.type_,
                self.type_regex):
            return False

        if self.range_ and not match_range(
                context.range_,
                self.range_,
                self.range_subset,
                self.range_overlap,
                self.range_superset,
                self.range_proper):
            return False

        return True


class MatchName:

    """Mixin for matching an object's name with alias dereferencing."""

    name = CriteriaDescriptor("name_regex")
    name_regex: bool = False
    alias_deref: bool = False

    def _match_name_debug(self, log: Logger) -> None:
        """Log debugging messages for name matching."""
        log.debug("Name: {0.name!r}, regex: {0.name_regex}, deref: {0.alias_deref}".format(self))

    def _match_name(self, obj):
        """Match the object to the name criteria."""
        if not self.name:
            # if there is no criteria, everything matches.
            return True

        if self.alias_deref:
            return match_regex(obj, self.name, self.name_regex) or \
                match_in_set(obj.aliases(), self.name, self.name_regex)
        else:
            return match_regex(obj, self.name, self.name_regex)


class MatchObjClass:

    """Mixin for matching an object's class."""

    tclass = CriteriaSetDescriptor("tclass_regex", "lookup_class")
    tclass_regex: bool = False

    def _match_object_class_debug(self, log: Logger) -> None:
        """Emit log debugging info for permission matching."""
        log.debug("Class: {0.tclass!r}, regex: {0.tclass_regex}".format(self))

    def _match_object_class(self, obj):
        """
        Match the object class criteria

        Parameter:
        obj     An object with an object class attribute named "tclass"
        """

        if not self.tclass:
            # if there is no criteria, everything matches.
            return True
        elif self.tclass_regex:
            return bool(self.tclass.search(str(obj.tclass)))
        else:
            return obj.tclass in self.tclass


class MatchPermission:

    """Mixin for matching an object's permissions."""

    perms = CriteriaPermissionSetDescriptor(name_regex="perms_regex")
    perms_equal: bool = False
    perms_regex: bool = False
    perms_subset: bool = False

    def _match_perms_debug(self, log: Logger):
        """Emit log debugging info for permission matching."""
        log.debug("Perms: {0.perms!r}, regex: {0.perms_regex}, eq: {0.perms_equal}, "
                  "subset: {0.perms_subset!r}".format(self))

    def _match_perms(self, obj):
        """
        Match the permission criteria

        Parameter:
        obj     An object with a permission set class attribute named "perms"
        """

        if not self.perms:
            # if there is no criteria, everything matches.
            return True

        if self.perms_subset:
            return obj.perms >= self.perms
        else:
            return match_regex_or_set(obj.perms, self.perms, self.perms_equal, self.perms_regex)


class NetworkXGraphEdge:

    """Mixin enabling use in NetworkX functions."""

    source: Any
    target: Any

    def __getitem__(self, key):
        # This is implemented so this object can be used in NetworkX
        # functions that operate on (source, target) tuples
        if isinstance(key, slice):
            return [self._index_to_item(i) for i in range(* key.indices(2))]
        else:
            return self._index_to_item(key)

    def _index_to_item(self, index: int):
        """Return source or target based on index."""
        if index == 0:
            return self.source
        elif index == 1:
            return self.target
        else:
            raise IndexError(f"Invalid index (NetworkXGraphEdge only has 2 items): {index}")


class TupleCompat:

    """Mixin for named tuple backwards compatibility for dataclasses."""

    def __getitem__(self, key):
        warnings.warn("Named tuple returns are deprecated, replaced with dataclasses.",
                      DeprecationWarning)
        return astuple(self)[key]

    def __iter__(self):
        warnings.warn("Named tuple returns are deprecated, replaced with dataclasses.",
                      DeprecationWarning)
        return iter(astuple(self))

    def __len__(self):
        warnings.warn("Named tuple returns are deprecated, replaced with dataclasses.",
                      DeprecationWarning)
        return len(astuple(self))
