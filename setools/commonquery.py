# Copyright 2014-2015, Tresys Technology, LLC
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

from . import compquery


class CommonQuery(compquery.ComponentQuery):

    """Query common permission sets."""

    def __init__(self, policy,
                 name="", name_regex=False,
                 perms=set(), perms_equal=False, perms_regex=False):
        """
        Parameters:
        name         The name of the common to match.
        name_regex   If true, regular expression matching will
                     be used for matching the name.
        perms        The permissions to match.
        perms_equal  If true, only commons with permission sets
                     that are equal to the criteria will
                     match.  Otherwise, any intersection
                     will match.
        perms_regex  If true, regular expression matching will be used
                     on the permission names instead of set logic.
        """

        self.policy = policy
        self.set_name(name, regex=name_regex)
        self.set_perms(perms, regex=perms_regex, equal=perms_equal)

    def results(self):
        """Generator which yields all matching commons."""

        for com in self.policy.commons():
            if self.name and not self._match_name(com):
                continue

            if self.perms and not self._match_regex_or_set(
                    com.perms,
                    self.perms_cmp,
                    self.perms_equal,
                    self.perms_regex):
                continue

            yield com

    def set_perms(self, perms, **opts):
        """
        Set the criteria for the common's permissions.

        Parameter:
        perms 		Name to match the common's permissions.

        Keyword Options:
        regex       If true, regular expression matching will be used.
        equal		If true, the permisison set of the common
                    must equal the permissions criteria to
                    match. If false, any intersection in the
                    critera will cause a match.

        Exceptions:
        NameError   Invalid keyword option.
        """

        self.perms = perms

        for k in list(opts.keys()):
            if k == "regex":
                self.perms_regex = opts[k]
            elif k == "equal":
                self.perms_equal = opts[k]
            else:
                raise NameError("Invalid permissions option: {0}".format(k))

        if self.perms_regex:
            self.perms_cmp = re.compile(self.perms)
        else:
            self.perms_cmp = self.perms
