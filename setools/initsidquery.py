# Copyright 2014-2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
import logging
from typing import Iterable

from .mixins import MatchContext, MatchName
from .policyrep import InitialSID
from .query import PolicyQuery


class InitialSIDQuery(MatchName, MatchContext, PolicyQuery):

    """
    Initial SID (Initial context) query.

    Parameter:
    policy            The policy to query.

    Keyword Parameters/Class attributes:
    name            The Initial SID name to match.
    name_regex      If true, regular expression matching
                    will be used on the Initial SID name.
    user            The criteria to match the context's user.
    user_regex      If true, regular expression matching
                    will be used on the user.
    role            The criteria to match the context's role.
    role_regex      If true, regular expression matching
                    will be used on the role.
    type_           The criteria to match the context's type.
    type_regex      If true, regular expression matching
                    will be used on the type.
    range_          The criteria to match the context's range.
    range_subset    If true, the criteria will match if it is a subset
                    of the context's range.
    range_overlap   If true, the criteria will match if it overlaps
                    any of the context's range.
    range_superset  If true, the criteria will match if it is a superset
                    of the context's range.
    range_proper    If true, use proper superset/subset operations.
                    No effect if not using set operations.
    """

    def __init__(self, policy, **kwargs):
        super(InitialSIDQuery, self).__init__(policy, **kwargs)
        self.log = logging.getLogger(__name__)

    def results(self) -> Iterable[InitialSID]:
        """Generator which yields all matching initial SIDs."""
        self.log.info("Generating initial SID results from {0.policy}".format(self))
        self._match_name_debug(self.log)
        self._match_context_debug(self.log)

        for i in self.policy.initialsids():
            if not self._match_name(i):
                continue

            if not self._match_context(i.context):
                continue

            yield i
