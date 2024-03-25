# Copyright 2014-2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from collections.abc import Iterable
import typing

from . import mixins, query, policyrep, util

__all__: typing.Final[tuple[str, ...]] = ("PortconQuery",)


class PortconQuery(mixins.MatchContext, query.PolicyQuery):

    """
    Port context query.

    Parameter:
    policy          The policy to query.

    Keyword Parameters/Class attributes:
    protocol        The protocol to match (socket.IPPROTO_TCP for
                    TCP or socket.IPPROTO_UDP for UDP)

    ports           A 2-tuple of the port range to match. (Set both to
                    the same value for a single port)
    ports_subset    If true, the criteria will match if it is a subset
                    of the portcon's range.
    ports_overlap   If true, the criteria will match if it overlaps
                    any of the portcon's range.
    ports_superset  If true, the criteria will match if it is a superset
                    of the portcon's range.
    ports_proper    If true, use proper superset/subset operations.
                    No effect if not using set operations.

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

    _protocol: policyrep.PortconProtocol | None = None
    _ports: policyrep.PortconRange | None = None
    ports_subset: bool = False
    ports_overlap: bool = False
    ports_superset: bool = False
    ports_proper: bool = False

    @property
    def ports(self) -> policyrep.PortconRange | None:
        return self._ports

    @ports.setter
    def ports(self, value: tuple[int, int] | None) -> None:
        if value:
            self._ports = policyrep.PortconRange(*value)
        else:
            self._ports = None

    @property
    def protocol(self) -> policyrep.PortconProtocol | None:
        return self._protocol

    @protocol.setter
    def protocol(self, value: policyrep.PortconProtocol | str | None) -> None:
        if value:
            self._protocol = policyrep.PortconProtocol.lookup(value)
        else:
            self._protocol = None

    def results(self) -> Iterable[policyrep.Portcon]:
        """Generator which yields all matching portcons."""
        self.log.info(f"Generating portcon results from {self.policy}")
        self.log.debug(f"{self.ports=}, {self.ports_overlap=}, {self.ports_subset=}, "
                       f"{self.ports_superset=}, {self.ports_proper=}")
        self.log.debug(f"Protocol: {self.protocol=}")
        self._match_context_debug(self.log)

        for portcon in self.policy.portcons():

            if self.ports and not util.match_range(
                    portcon.ports,
                    self.ports,
                    self.ports_subset,
                    self.ports_overlap,
                    self.ports_superset,
                    self.ports_proper):
                continue

            if self.protocol and self.protocol != portcon.protocol:
                continue

            if not self._match_context(portcon.context):
                continue

            yield portcon
