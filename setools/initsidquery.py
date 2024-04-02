# Copyright 2014-2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from collections.abc import Iterable
import typing

from . import mixins, policyrep, query

__all__: typing.Final[tuple[str, ...]] = ("InitialSIDQuery",)


class InitialSIDQuery(mixins.MatchName, mixins.MatchContext, query.PolicyQuery):

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

    def results(self) -> Iterable[policyrep.InitialSID]:
        """Generator which yields all matching initial SIDs."""
        self.log.info(f"Generating initial SID results from {self.policy}")
        self._match_name_debug(self.log)
        self._match_context_debug(self.log)

        for i in self.policy.initialsids():
            if not self._match_name(i):
                continue

            if not self._match_context(i.context):
                continue

            yield i
