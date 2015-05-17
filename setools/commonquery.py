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
import logging
import re

from . import compquery, mixins


class CommonQuery(mixins.MatchPermission, compquery.ComponentQuery):

    """
    Query common permission sets.

    Parameter:
    policy       The policy to query.

    Keyword Parameters/Class attributes:
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

    def results(self):
        """Generator which yields all matching commons."""
        self.log.info("Generating results from {0.policy}".format(self))
        self.log.debug("Name: {0.name!r}, regex: {0.name_regex}".format(self))
        self.log.debug("Perms: {0.perms!r}, regex: {0.perms_regex}, eq: {0.perms_equal}".
                       format(self))

        for com in self.policy.commons():
            if not self._match_name(com):
                continue

            if not self._match_perms(com):
                continue

            yield com
