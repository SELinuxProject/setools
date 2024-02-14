# Copyright 2014-2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from typing import Iterable

from .mixins import MatchName
from .policyrep import PolicyCapability
from .query import PolicyQuery


class PolCapQuery(MatchName, PolicyQuery):

    """
    Query SELinux policy capabilities

    Parameter:
    policy      The policy to query.

    Keyword Parameters/Class attributes:
    name        The name of the policy capability to match.
    name_regex  If true, regular expression matching will
                be used for matching the name.
    """

    def results(self) -> Iterable[PolicyCapability]:
        """Generator which yields all matching policy capabilities."""
        self.log.info("Generating policy capability results from {0.policy}".format(self))
        self._match_name_debug(self.log)

        for cap in self.policy.polcaps():
            if not self._match_name(cap):
                continue

            yield cap
