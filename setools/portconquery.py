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
from socket import IPPROTO_TCP, IPPROTO_UDP

from . import compquery
from . import contextquery


class PortconQuery(compquery.ComponentQuery, contextquery.ContextQuery):

    """Port context query."""

    def __init__(self, policy,
                 protocol=0,
                 ports=(0, 0), ports_subset=False, ports_overlap=False,
                 ports_superset=False, ports_proper=False,
                 user="", user_regex=False,
                 role="", role_regex=False,
                 type_="", type_regex=False,
                 range_="", range_overlap=False, range_subset=False,
                 range_superset=False, range_proper=False):
        """
        Parameters:
        policy          The policy to query.

        Keyword Parameters:
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

        self.policy = policy

        self.set_protocol(protocol)
        self.set_ports(ports, subset=ports_subset, overlap=ports_overlap,
                       superset=ports_superset, proper=ports_proper)
        self.set_user(user, regex=user_regex)
        self.set_role(role, regex=role_regex)
        self.set_type(type_, regex=type_regex)
        self.set_range(range_, overlap=range_overlap, subset=range_subset,
                       superset=range_superset, proper=range_proper)

    def results(self):
        """Generator which yields all matching portcons."""

        for p in self.policy.portcons():

            if any(self.ports):
                if not self._match_range(
                        p.ports,
                        self.ports,
                        self.subset,
                        self.overlap,
                        self.superset,
                        self.proper):
                    continue

            if self.protocol and self.protocol != p.protocol:
                continue

            if not self._match_context(
                    p.context,
                    self.user_cmp,
                    self.user_regex,
                    self.role_cmp,
                    self.role_regex,
                    self.type_cmp,
                    self.type_regex,
                    self.range_cmp,
                    self.range_subset,
                    self.range_overlap,
                    self.range_superset,
                    self.range_proper):
                continue

            yield p

    def set_ports(self, ports, **opts):
        """
        Set the criteria for matching the port range.

        Parameter:
        ports       A 2-tuple of the port range to match. (Set both to
                    the same value to match a single port)

        Keyword Parameters:
        subset      If true, the criteria will match if it is a subset
                    of the portcon's range.
        overlap     If true, the criteria will match if it overlaps
                    any of the portcon's range.
        superset    If true, the criteria will match if it is a superset
                    of the portcon's range.
        proper      If true, use proper superset/subset operations.
                    No effect if not using set operations.
        """

        pending_ports = (int(ports[0]), int(ports[1]))

        if (pending_ports[0] < 0 or pending_ports[1] < 0):
            raise ValueError("Port numbers must be positive: {0[0]}-{0[1]}".format(ports))

        if (pending_ports[0] > pending_ports[1]):
            raise ValueError(
                "The low port must be smaller than the high port: {0[0]}-{0[1]}".format(ports))

        self.ports = pending_ports

        for k in list(opts.keys()):
            if k == "subset":
                self.subset = opts[k]
            elif k == "overlap":
                self.overlap = opts[k]
            elif k == "superset":
                self.superset = opts[k]
            elif k == "proper":
                self.proper = opts[k]
            else:
                raise NameError("Invalid name option: {0}".format(k))

    def set_protocol(self, protocol):
        """
        Set the criteria for matching the IP protocol.

        Parameter:
        version     The protocol number to match.  (socket.IPPROTO_TCP for
                    TCP or socket.IPPROTO_UDP for UDP)

        Exceptions:
        ValueError  Invalid protocol number.
        """

        if protocol:
            if not (protocol == IPPROTO_TCP or protocol == IPPROTO_UDP):
                raise ValueError(
                    "The protocol must be {0} for TCP or {1} for UDP.".
                    format(IPPROTO_TCP, IPPROTO_UDP))

            self.protocol = protocol

        else:
            self.protocol = None
