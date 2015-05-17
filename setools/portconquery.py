# Copyright 2014-2015, Tresys Technology, LLC
#
# This file is part of SETools.
#
# SETools is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation, either version 2.1 of
# the License, or (at your option) any later version.
#
# SETools is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with SETools.  If not, see
# <http://www.gnu.org/licenses/>.
#
import logging
from socket import IPPROTO_TCP, IPPROTO_UDP

from . import contextquery
from .policyrep.netcontext import port_range


class PortconQuery(contextquery.ContextQuery):

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

    _protocol = None
    _ports = None
    ports_subset = False
    ports_overlap = False
    ports_superset = False
    ports_proper = False

    @property
    def ports(self):
        return self._ports

    @ports.setter
    def ports(self, value):
        pending_ports = port_range(*value)

        if all(pending_ports):
            if pending_ports.low < 1 or pending_ports.high < 1:
                raise ValueError("Port numbers must be positive: {0.low}-{0.high}".
                                 format(pending_ports))

            if pending_ports.low > pending_ports.high:
                raise ValueError(
                    "The low port must be smaller than the high port: {0.low}-{0.high}".
                    format(pending_ports))

            self._ports = pending_ports
        else:
            self._ports = None

    @property
    def protocol(self):
        return self._protocol

    @protocol.setter
    def protocol(self, value):
        if value:
            if not (value == IPPROTO_TCP or value == IPPROTO_UDP):
                raise ValueError(
                    "The protocol must be {0} for TCP or {1} for UDP.".
                    format(IPPROTO_TCP, IPPROTO_UDP))

            self._protocol = value
        else:
            self._protocol = None

    def results(self):
        """Generator which yields all matching portcons."""
        self.log.info("Generating results from {0.policy}".format(self))
        self.log.debug("Ports: {0.ports}, overlap: {0.ports_overlap}, "
                       "subset: {0.ports_subset}, superset: {0.ports_superset}, "
                       "proper: {0.ports_proper}".format(self))
        self.log.debug("User: {0.user!r}, regex: {0.user_regex}".format(self))
        self.log.debug("Role: {0.role!r}, regex: {0.role_regex}".format(self))
        self.log.debug("Type: {0.type_!r}, regex: {0.type_regex}".format(self))
        self.log.debug("Range: {0.range_!r}, subset: {0.range_subset}, overlap: {0.range_overlap}, "
                       "superset: {0.range_superset}, proper: {0.range_proper}".format(self))

        for portcon in self.policy.portcons():

            if self.ports and not self._match_range(
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
