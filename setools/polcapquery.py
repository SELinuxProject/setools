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

from . import compquery


class PolCapQuery(compquery.ComponentQuery):

    """
    Query SELinux policy capabilities

    Parameter:
    policy      The policy to query.

    Keyword Parameters/Class attributes:
    name        The name of the policy capability to match.
    name_regex  If true, regular expression matching will
                be used for matching the name.
    """

    def results(self):
        """Generator which yields all matching policy capabilities."""
        self.log.info("Generating results from {0.policy}".format(self))
        self.log.debug("Name: {0.name!r}, regex: {0.name_regex}".format(self))

        for cap in self.policy.polcaps():
            if not self._match_name(cap):
                continue

            yield cap
