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
from . import compquery
from . import contextquery


class NetifconQuery(compquery.ComponentQuery, contextquery.ContextQuery):

    """Network interface context query."""

    def __init__(self, policy,
                 name=None, name_regex=False,
                 user=None, user_regex=False,
                 role=None, role_regex=False,
                 type_=None, type_regex=False,
                 range_=None, range_overlap=False, range_subset=False,
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
        """Generator which yields all matching netifcons."""

        for netif in self.policy.netifcons():
            if self.name and not self._match_regex(
                    netif.netif,
                    self.name_cmp,
                    self.name_regex):
                continue

            if not self._match_context(
                    netif.context,
                    self.user_cmp,
                    self.user_regex,
                    self.role_cmp,
                    self.role_regex,
                    self.type_cmp,
                    self.type_regex,
                    self.range_cmp,
                    self.range_subset,
                    self.range_overlap,
                    self.range_superset,
                    self.range_proper):
                continue

            yield netif
