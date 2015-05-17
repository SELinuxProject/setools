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

    def _match_perms(self, obj):
        """
        Match the permission criteria

        Parameter:
        obj     An object with a permission set class attribute named "perms"
        """

        if not self.perms:
            # if there is no criteria, everything matches.
            return True

        return self._match_regex_or_set(obj.perms, self.perms, self.perms_equal, self.perms_regex)
