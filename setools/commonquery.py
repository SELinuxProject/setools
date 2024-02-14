# Copyright 2014-2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from typing import Iterable

from .mixins import MatchName, MatchPermission
from .policyrep import Common
from .query import PolicyQuery


class CommonQuery(MatchPermission, MatchName, PolicyQuery):

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

    def results(self) -> Iterable[Common]:
        """Generator which yields all matching commons."""
        self.log.info("Generating common results from {0.policy}".format(self))
        self._match_name_debug(self.log)
        self._match_perms_debug(self.log)

        for com in self.policy.commons():
            if not self._match_name(com):
                continue

            if not self._match_perms(com):
                continue

            yield com
