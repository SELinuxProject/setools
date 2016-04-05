# Copyright 2015, Tresys Technology, LLC
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
# pylint: disable=attribute-defined-outside-init,no-member
import re

from .descriptors import CriteriaDescriptor, CriteriaSetDescriptor


class MatchAlias(object):

    """Mixin for matching an object's aliases."""

    alias = CriteriaDescriptor("alias_regex")
    alias_regex = False

    def _match_alias_debug(self, log):
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

        return self._match_in_set(obj.aliases(), self.alias, self.alias_regex)


class MatchObjClass(object):

    """Mixin for matching an object's class."""

    tclass = CriteriaSetDescriptor("tclass_regex", "lookup_class")
    tclass_regex = False

    def _match_object_class_debug(self, log):
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


class MatchPermission(object):

    """Mixin for matching an object's permissions."""

    perms = CriteriaSetDescriptor("perms_regex")
    perms_equal = False
    perms_regex = False
    perms_subset = False

    def _match_perms_debug(self, log):
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
            return self._match_regex_or_set(obj.perms, self.perms, self.perms_equal,
                                            self.perms_regex)
