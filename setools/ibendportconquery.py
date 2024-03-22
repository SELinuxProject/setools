# Copyright 2018, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from collections.abc import Iterable
import typing

from . import mixins, policyrep, query, util

__all__: typing.Final[tuple[str, ...]] = ("IbendportconQuery",)


class IbendportconQuery(mixins.MatchContext, mixins.MatchName, query.PolicyQuery):

    """
    Infiniband endport context query.

    Parameter:
    policy          The policy to query.

    Keyword Parameters/Class attributes:
    name            The name of the network interface to match.
    name_regex      If true, regular expression matching will
                    be used for matching the name.
    port            The port number to match.
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

    _port: int | None = None

    @property
    def port(self) -> int | None:
        return self._port

    @port.setter
    def port(self, value: int | None) -> None:
        if value:
            pending_value = int(value)
            if not 0 < pending_value < 256:
                raise ValueError(f"Endport value must be 1-255: {pending_value}")

            self._port = pending_value
        else:
            self._port = None

    def results(self) -> Iterable[policyrep.Ibendportcon]:
        """Generator which yields all matching ibendportcons."""
        self.log.info(f"Generating ibendportcon results from {self.policy}")
        self._match_name_debug(self.log)
        self.log.debug(f"{self.port=}")
        self._match_context_debug(self.log)

        for endport in self.policy.ibendportcons():
            if self.name and not util.match_regex(
                    endport.name,
                    self.name,
                    self.name_regex):
                continue

            if self.port is not None and self.port != endport.port:
                continue

            if not self._match_context(endport.context):
                continue

            yield endport
