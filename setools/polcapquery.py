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

from . import compquery


class PolCapQuery(compquery.ComponentQuery):

    """Query SELinux policy capabilities"""

    def __init__(self, policy,
                 name=None, name_regex=False):
        """
        Parameters:
        name        The name of the policy capability to match.
        name_regex  If true, regular expression matching will
                    be used for matching the name.
        """
        self.log = logging.getLogger(self.__class__.__name__)

        self.policy = policy
        self.set_name(name, regex=name_regex)

    def results(self):
        """Generator which yields all matching policy capabilities."""
        self.log.info("Generating results from {0.policy}".format(self))
        self.log.debug("Name: {0.name_cmp!r}, regex: {0.name_regex}".format(self))

        for cap in self.policy.polcaps():
            if self.name and not self._match_name(cap):
                continue

            yield cap
