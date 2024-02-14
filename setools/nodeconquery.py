# Copyright 2014-2015, Tresys Technology, LLC
# Copyright 2017, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: LGPL-2.1-only
#
import ipaddress

from typing import Iterable, Optional, Union

from .mixins import MatchContext
from .policyrep import Nodecon, NodeconIPVersion
from .query import PolicyQuery

AnyIPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


class NodeconQuery(MatchContext, PolicyQuery):

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

    _network: Optional[AnyIPNetwork] = None
    network_overlap: bool = False
    _ip_version: Optional[NodeconIPVersion] = None

    @property
    def ip_version(self) -> Optional[NodeconIPVersion]:
        return self._ip_version

    @ip_version.setter
    def ip_version(self, value: Optional[Union[str, NodeconIPVersion]]) -> None:
        if value:
            self._ip_version = NodeconIPVersion.lookup(value)
        else:
            self._ip_version = None

    @property
    def network(self) -> Optional[AnyIPNetwork]:
        return self._network

    @network.setter
    def network(self, value: Optional[Union[str, AnyIPNetwork]]) -> None:
        if value:
            self._network = ipaddress.ip_network(value)
        else:
            self._network = None

    def results(self) -> Iterable[Nodecon]:
        """Generator which yields all matching nodecons."""
        self.log.info("Generating nodecon results from {0.policy}".format(self))
        self.log.debug("Network: {0.network!r}, overlap: {0.network_overlap}".format(self))
        self.log.debug("IP Version: {0.ip_version!r}".format(self))
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
