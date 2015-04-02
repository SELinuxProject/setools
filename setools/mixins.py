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
import re


class MatchAlias(object):

    """Mixin for matching an object's aliases."""

    def _match_alias(self, obj):
        """Match the object to the alias criteria."""
        return self._match_in_set(obj, self.alias_cmp, self.alias_regex)

    def set_alias(self, alias, **opts):
        """
        Set the criteria for the component's aliases.

        Parameter:
        alias       Name to match the component's aliases.

        Keyword Options:
        regex       If true, regular expression matching will be used.

        Exceptions:
        NameError   Invalid keyword option.
        """

        self.alias = alias

        for k in list(opts.keys()):
            if k == "regex":
                self.alias_regex = opts[k]
            else:
                raise NameError("Invalid alias option: {0}".format(k))

        if not self.alias:
            self.alias_cmp = None
        elif self.alias_regex:
            self.alias_cmp = re.compile(self.alias)
        else:
            self.alias_cmp = self.alias


class MatchObjClass(object):

    def _match_object_class(self, obj):
        """Match the object class criteria"""

        if isinstance(self.tclass_cmp, set):
            return obj in self.tclass_cmp
        elif self.tclass_regex:
            return bool(self.tclass_cmp.search(str(obj)))
        else:
            return obj == self.tclass_cmp

    def set_tclass(self, tclass, **opts):
        """
        Set the object class(es) for the rule query.

        Parameter:
        tclass      The name of the object classes to match.
                    This must be a string if regular expression
                    matching is used.

        Keyword Options:
        regex       If true, use a regular expression for
                    matching the object class. If false, any
                    set intersection will match.

        Exceptions:
        NameError   Invalid keyword option.
        """

        self.tclass = tclass

        for k in list(opts.keys()):
            if k == "regex":
                self.tclass_regex = opts[k]
            else:
                raise NameError("Invalid object class option: {0}".format(k))

        if not self.tclass:
            self.tclass_cmp = None
        elif self.tclass_regex:
            self.tclass_cmp = re.compile(self.tclass)
        elif isinstance(self.tclass, str):
            self.tclass_cmp = self.policy.lookup_class(self.tclass)
        else:
            self.tclass_cmp = set(self.policy.lookup_class(c) for c in self.tclass)


class MatchPermission(object):

    """Mixin for matching an object's permissions."""

    def _match_perms(self, obj):
        """Match the object to the permission criteria."""
        return self._match_set(obj, self.perms_cmp, self.perms_equal)

    def set_perms(self, perms, **opts):
        """
        Set the permission set for the TE rule query.

        Parameter:
        perms       The permissions to match.

        Options:
        equal       If true, the permission set of the rule
                    must equal the permissions criteria to
                    match. If false, permission in the critera
                    will cause a rule match.

        Exceptions:
        NameError   Invalid permission set keyword option.
        """

        self.perms = perms

        for k in list(opts.keys()):
            if k == "equal":
                self.perms_equal = opts[k]
            else:
                raise NameError("Invalid permission set option: {0}".format(k))

        if not self.perms:
            self.perms_cmp = None
        else:
            self.perms_cmp = set(self.perms)
