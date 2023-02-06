# Copyright 2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
import logging
from typing import Iterable

from .descriptors import CriteriaDescriptor
from .mixins import MatchAlias, MatchName
from .policyrep import Sensitivity
from .query import PolicyQuery
from .util import match_level


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

    sens = CriteriaDescriptor(lookup_function="lookup_sensitivity")
    sens_dom: bool = False
    sens_domby: bool = False

    def __init__(self, policy, **kwargs) -> None:
        super(SensitivityQuery, self).__init__(policy, **kwargs)
        self.log = logging.getLogger(__name__)

    def results(self) -> Iterable[Sensitivity]:
        """Generator which yields all matching sensitivities."""
        self.log.info("Generating sensitivity results from {0.policy}".format(self))
        self._match_name_debug(self.log)
        self._match_alias_debug(self.log)
        self.log.debug("Sens: {0.sens!r}, dom: {0.sens_dom}, domby: {0.sens_domby}".format(self))

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
