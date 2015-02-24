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
from . import compquery
from . import contextquery


class InitialSIDQuery(compquery.ComponentQuery, contextquery.ContextQuery):

    """Initial SID (context) query."""

    def __init__(self, policy,
                 name="", name_regex=False,
                 user="", user_regex=False,
                 role="", role_regex=False,
                 type_="", type_regex=False,
                 range_="", range_overlap=False, range_subset=False,
                 range_superset=False, range_proper=False):
        """
        Parameters:
        policy          The policy to query.

        user            The criteria to match the context's user.
        user_regex      If true, regular expression matching
                        will be used on the user.
        role            The criteria to match the context's role.
        role_regex      If true, regular expression matching
                        will be used on the role.
        type_           The criteria to match the context's type.
        type_regex      If true, regular expression matching
                        will be used on the type.
        range_          The criteria to match the context's range.
        range_subset    If true, the criteria will match if it is a subset
                        of the context's range.
        range_overlap   If true, the criteria will match if it overlaps
                        any of the context's range.
        range_superset  If true, the criteria will match if it is a superset
                        of the context's range.
        range_proper    If true, use proper superset/subset operations.
                        No effect if not using set operations.
        """

        self.policy = policy

        self.set_name(name, regex=name_regex)
        self.set_user(user, regex=user_regex)
        self.set_role(role, regex=role_regex)
        self.set_type(type_, regex=type_regex)
        self.set_range(range_, overlap=range_overlap, subset=range_subset,
                       superset=range_superset, proper=range_proper)

    def results(self):
        """Generator which yields all matching initial SIDs."""

        for i in self.policy.initialsids():
            if self.name and not self._match_regex(
                    i,
                    self.name,
                    self.name_regex,
                    self.name_cmp):
                continue

            if not self._match_context(
                    i.context,
                    self.user,
                    self.user_regex,
                    self.user_cmp,
                    self.role,
                    self.role_regex,
                    self.role_cmp,
                    self.type_,
                    self.type_regex,
                    self.type_cmp,
                    self.range_,
                    self.range_subset,
                    self.range_overlap,
                    self.range_superset,
                    self.range_proper):
                continue

            yield i
