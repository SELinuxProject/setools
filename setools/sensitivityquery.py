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

from . import compquery
from . import mixins


class SensitivityQuery(mixins.MatchAlias, compquery.ComponentQuery):

    """Query MLS Sensitivities"""

    def __init__(self, policy,
                 name=None, name_regex=False,
                 alias=None, alias_regex=False,
                 sens=None, sens_dom=False, sens_domby=False):
        """
        Parameters:
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

        self.policy = policy
        self.set_name(name, regex=name_regex)
        self.set_alias(alias, regex=alias_regex)
        self.set_sensitivity(sens, dom=sens_dom, domby=sens_domby)

    def results(self):
        """Generator which yields all matching sensitivities."""

        for s in self.policy.sensitivities():
            if self.name and not self._match_name(s):
                continue

            if self.alias and not self._match_alias(s.aliases()):
                continue

            if self.sens and not self._match_level(
                    s,
                    self.sens,
                    self.sens_dom,
                    self.sens_domby,
                    False):
                continue

            yield s

    def set_sensitivity(self, sens, **opts):
        """
        Set the criteria for matching the sensitivity by dominance.

        Parameter:
        sens        Criteria to match the sensitivity.

        Keyword Parameters:
        dom         If true, the criteria will match if it
                    dominates the sensitivity.
        domby       If true, the criteria will match if it
                    is dominated by the sensitivity.

        Exceptions:
        NameError   Invalid keyword option.
        """

        if sens:
            self.sens = self.policy.lookup_sensitivity(sens)
        else:
            self.sens = None

        for k in list(opts.keys()):
            if k == "dom":
                self.sens_dom = opts[k]
            elif k == "domby":
                self.sens_domby = opts[k]
            else:
                raise NameError("Invalid name option: {0}".format(k))
