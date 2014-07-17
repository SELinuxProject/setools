# Copyright 2014, Tresys Technology, LLC
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

import compquery


class UserQuery(compquery.ComponentQuery):

    """Query SELinux policy users."""

    def __init__(self, policy,
                 name="", name_regex=False,
                 roles=set(), roles_equal=False, roles_regex=False):
        """
        Parameter:
        policy	     The policy to query.
        name         The user name to match.
        name_regex   If true, regular expression matching
                     will be used on the user names.
        roles        The attribute to match.
        roles_equal  If true, only types with role sets
                     that are equal to the criteria will
                     match.  Otherwise, any intersection
                     will match.
        roles_regex  If true, regular expression matching
                     will be used on the role names.
        """

        self.policy = policy
        self.set_name(name, regex=name_regex)
        self.set_roles(roles, regex=roles_regex, equal=roles_equal)

    def results(self):
        """Generator which yields all matching users."""

        for u in self.policy.users():
            if self.name and not self._match_regex(
                    u,
                    self.name,
                    self.name_regex,
                    self.name_cmp):
                continue

            if self.roles and not self._match_regex_or_set(
                    set(str(r) for r in u.roles),
                    self.roles,
                    self.roles_equal,
                    self.roles_regex,
                    self.roles_cmp):
                continue

            # TODO: default level and range

            yield u

    def set_roles(self, roles, **opts):
        """
        Set the criteria for the users's roles.

        Parameter:
        roles 		Name to match the component's attributes.

        Keyword Options:
        regex       If true, regular expression matching will be used.
        equal		If true, the role set of the user
                    must equal the attributes criteria to
                    match. If false, any intersection in the
                    critera will cause a rule match.

        Exceptions:
        NameError   Invalid keyword option.
        """

        self.roles = roles

        for k in opts.keys():
            if k == "regex":
                self.roles_regex = opts[k]
            elif k == "equal":
                self.roles_equal = opts[k]
            else:
                raise NameError("Invalid roles option: {0}".format(k))

        if self.roles_regex:
            self.roles_cmp = re.compile(self.roles)
        else:
            self.roles_cmp = None
