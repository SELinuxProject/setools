# Copyright 2014-2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from collections.abc import Iterable
import typing

from . import mixins, policyrep, query

__all__: typing.Final[tuple[str, ...]] = ()


class NetifconQuery(mixins.MatchContext, mixins.MatchName, query.PolicyQuery):

    """
    Network interface context query.

    Parameter:
    policy          The policy to query.

    Keyword Parameters/Class attributes:
    name            The name of the network interface to match.
    name_regex      If true, regular expression matching will
                    be used for matching the name.
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

    required_platform = policyrep.PolicyTarget.selinux

    def results(self) -> Iterable[policyrep.Netifcon]:
        """Generator which yields all matching netifcons."""
        self.log.info(f"Generating netifcon results from {self.policy}")
        self._match_name_debug(self.log)
        self._match_context_debug(self.log)

        for netif in self.policy.netifcons():
            if not self._match_name(netif.netif):
                continue

            if not self._match_context(netif.context):
                continue

            yield netif
