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


class BoolQuery(compquery.ComponentQuery):

    """Query SELinux policy Booleans."""

    def __init__(self, policy,
                 name=None, name_regex=False,
                 default=False, match_default=False):
        """
        Parameter:
        policy          The policy to query.
        name            The Boolean name to match.
        name_regex      If true, regular expression matching
                        will be used on the Boolean name.
        default         The default state to match.
        match_default   If true, the default state will be matched.
        """
        self.log = logging.getLogger(self.__class__.__name__)

        self.policy = policy
        self.set_name(name, regex=name_regex)
        self.set_default(match_default, default=default)

    def results(self):
        """Generator which yields all Booleans matching the criteria."""
        self.log.info("Generating results from {0.policy}".format(self))
        self.log.debug("Name: {0.name_cmp!r}, regex: {0.name_regex}".format(self))
        self.log.debug("Default: {0.match_default}, state: {0.default}".format(self))

        for b in self.policy.bools():
            if self.name and not self._match_name(b):
                continue

            if self.match_default and b.state() != self.default:
                continue

            yield b

    def set_default(self, match, **opts):
        """
        Set if the default Boolean state should be matched.

        Parameter:
        match       If true, the default state will be matched.
        default     The default state to match.

        Exceptions:
        NameError   Invalid keyword option.
        """

        self.match_default = bool(match)

        for k in list(opts.keys()):
            if k == "default":
                self.default = bool(opts[k])
            else:
                raise NameError("Invalid default option: {0}".format(k))
