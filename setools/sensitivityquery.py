# Copyright 2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from collections.abc import Iterable

from . import policyrep
from .descriptors import CriteriaDescriptor
from .mixins import MatchAlias, MatchName
from .query import PolicyQuery


class SensitivityQuery(MatchAlias, MatchName, PolicyQuery):

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

    sens = CriteriaDescriptor[policyrep.Sensitivity](lookup_function="lookup_sensitivity")
    sens_dom: bool = False
    sens_domby: bool = False

    def results(self) -> Iterable[policyrep.Sensitivity]:
        """Generator which yields all matching sensitivities."""
        self.log.info(f"Generating sensitivity results from {self.policy}")
        self._match_name_debug(self.log)
        self._match_alias_debug(self.log)
        self.log.debug(f"{self.sens=}, {self.sens_dom=}, {self.sens_domby=}")

        for s in self.policy.sensitivities():
            if not self._match_name(s):
                continue

            if not self._match_alias(s):
                continue

            if self.sens:
                if self.sens_dom:
                    if self.sens < s:
                        continue
                elif self.sens_domby:
                    if self.sens > s:
                        continue
                elif self.sens != s:
                    continue

            yield s
