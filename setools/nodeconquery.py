# Copyright 2014-2015, Tresys Technology, LLC
# Copyright 2017, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from collections.abc import Iterable
import ipaddress
import typing

from . import mixins, policyrep, query

AnyIPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

__all__: typing.Final[tuple[str, ...]] = ("AnyIPNetwork", "NodeconQuery")


class NodeconQuery(mixins.MatchContext, query.PolicyQuery):

    """
    Query nodecon statements.

    Parameter:
    policy          The policy to query.

    Keyword Parameters/Class attributes:
    network         The IPv4/IPv6 address or IPv4/IPv6 network address
                    with netmask, e.g. 192.168.1.0/255.255.255.0 or
                    "192.168.1.0/24".
    network_overlap If true, the net will match if it overlaps with
                    the nodecon's network instead of equality.
    ip_version      The IP version of the nodecon to match. (socket.AF_INET
                    for IPv4 or socket.AF_INET6 for IPv6)
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

    _network: AnyIPNetwork | None = None
    network_overlap: bool = False
    _ip_version: policyrep.NodeconIPVersion | None = None

    @property
    def ip_version(self) -> policyrep.NodeconIPVersion | None:
        return self._ip_version

    @ip_version.setter
    def ip_version(self, value: policyrep.NodeconIPVersion | str | None) -> None:
        if value:
            self._ip_version = policyrep.NodeconIPVersion.lookup(value)
        else:
            self._ip_version = None

    @property
    def network(self) -> AnyIPNetwork | None:
        return self._network

    @network.setter
    def network(self, value: AnyIPNetwork | str | None) -> None:
        if value:
            self._network = ipaddress.ip_network(value)
        else:
            self._network = None

    def results(self) -> Iterable[policyrep.Nodecon]:
        """Generator which yields all matching nodecons."""
        self.log.info(f"Generating nodecon results from {self.policy}")
        self.log.debug(f"{self.network=}, {self.network_overlap=}")
        self.log.debug(f"{self.ip_version=}")
        self._match_context_debug(self.log)

        for nodecon in self.policy.nodecons():

            if self.network:
                if self.network_overlap:
                    if not self.network.overlaps(nodecon.network):
                        continue
                else:
                    if not nodecon.network == self.network:
                        continue

            if self.ip_version and self.ip_version != nodecon.ip_version:
                continue

            if not self._match_context(nodecon.context):
                continue

            yield nodecon
