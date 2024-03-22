# Copyright 2014-2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from collections.abc import Iterable
import typing

from . import mixins, policyrep, query

__all__: typing.Final[tuple[str, ...]] = ("PolCapQuery",)


class PolCapQuery(mixins.MatchName, query.PolicyQuery):

    """
    Query SELinux policy capabilities

    Parameter:
    policy      The policy to query.

    Keyword Parameters/Class attributes:
    name        The name of the policy capability to match.
    name_regex  If true, regular expression matching will
                be used for matching the name.
    """

    def results(self) -> Iterable[policyrep.PolicyCapability]:
        """Generator which yields all matching policy capabilities."""
        self.log.info(f"Generating policy capability results from {self.policy}")
        self._match_name_debug(self.log)

        for cap in self.policy.polcaps():
            if not self._match_name(cap):
                continue

            yield cap
