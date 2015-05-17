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
import logging

from . import compquery
from . import mixins
from .descriptors import CriteriaDescriptor


class SensitivityQuery(mixins.MatchAlias, compquery.ComponentQuery):

    """
    Query MLS Sensitivities

    Parameter:
    policy       The policy to query.

    Keyword Parameters/Class attributes:
    name         The name of the category to match.
    name_regex   If true, regular expression matching will
                 be used for matching the name.
    alias        The alias name to match.
    alias_regex  If true, regular expression matching
                 will be used on the alias names.
    sens         The criteria to match the sensitivity by dominance.
    sens_dom     If true, the criteria will match if it dominates
                 the sensitivity.
    sens_domby   If true, the criteria will match if it is dominated
                 by the sensitivity.
    """

    sens = CriteriaDescriptor(lookup_function="lookup_sensitivity")
    sens_dom = False
    sens_domby = False

    def results(self):
        """Generator which yields all matching sensitivities."""
        self.log.info("Generating results from {0.policy}".format(self))
        self.log.debug("Name: {0.name!r}, regex: {0.name_regex}".format(self))
        self.log.debug("Alias: {0.alias}, regex: {0.alias_regex}".format(self))
        self.log.debug("Sens: {0.sens!r}, dom: {0.sens_dom}, domby: {0.sens_domby}".format(self))

        for s in self.policy.sensitivities():
            if not self._match_name(s):
                continue

            if not self._match_alias(s):
                continue

            if self.sens and not self._match_level(
                    s,
                    self.sens,
                    self.sens_dom,
                    self.sens_domby,
                    False):
                continue

            yield s
