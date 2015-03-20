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
try:
    import ipaddress
except ImportError:  # pragma: no cover
    pass

import logging
import re
from socket import AF_INET, AF_INET6

from . import compquery
from . import contextquery


class NodeconQuery(contextquery.ContextQuery):

    """Query nodecon statements."""

    def __init__(self, policy,
                 net=None, net_overlap=False,
                 version=None,
                 user=None, user_regex=False,
                 role=None, role_regex=False,
                 type_=None, type_regex=False,
                 range_=None, range_overlap=False, range_subset=False,
                 range_superset=False, range_proper=False):
        """
        Parameters:
        policy          The policy to query.

        net             The network address.
        overlap         If true, the net will match if it overlaps with
                        the nodecon's network instead of equality.
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
        self.log = logging.getLogger(self.__class__.__name__)

        self.policy = policy

        self.set_network(net, overlap=net_overlap)
        self.set_ip_version(version)
        self.set_user(user, regex=user_regex)
        self.set_role(role, regex=role_regex)
        self.set_type(type_, regex=type_regex)
        self.set_range(range_, overlap=range_overlap, subset=range_subset,
                       superset=range_superset, proper=range_proper)

    def results(self):
        """Generator which yields all matching nodecons."""
        self.log.info("Generating results from {0.policy}".format(self))
        self.log.debug("Network: {0.network!r}, overlap: {0.network_overlap}".format(self))
        self.log.debug("Ver: {0.version}".format(self))
        self.log.debug("User: {0.user_cmp!r}, regex: {0.user_regex}".format(self))
        self.log.debug("Role: {0.role_cmp!r}, regex: {0.role_regex}".format(self))
        self.log.debug("Type: {0.type_cmp!r}, regex: {0.type_regex}".format(self))
        self.log.debug("Range: {0.range_!r}, subset: {0.range_subset}, overlap: {0.range_overlap}, "
                       "superset: {0.range_superset}, proper: {0.range_proper}".format(self))

        for n in self.policy.nodecons():

            if self.network:
                try:
                    netmask = ipaddress.ip_address(n.netmask)
                except NameError:  # pragma: no cover
                    # Should never actually hit this since the self.network
                    # setter raises the same exception.
                    raise RuntimeError("IP address/network functions require Python 3.3+.")

                # Python 3.3's IPv6Network constructor does not support
                # expanded netmasks, only CIDR numbers. Convert netmask
                # into CIDR.
                # This is Brian Kernighan's method for counting set bits.
                # If the netmask happens to be invalid, this will
                # not detect it.
                CIDR = 0
                int_netmask = int(netmask)
                while int_netmask:
                    int_netmask &= int_netmask - 1
                    CIDR += 1

                net = ipaddress.ip_network('{0}/{1}'.format(n.address, CIDR))

                if self.network_overlap:
                    if not self.network.overlaps(net):
                        continue
                else:
                    if not net == self.network:
                        continue

            if self.version and self.version != n.ip_version:
                continue

            if not self._match_context(
                    n.context,
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

            yield n

    def set_network(self, net, **opts):
        """
        Set the criteria for matching the network.

        Parameter:
        net         String IPv4/IPv6 address or IPv4/IPv6 network address
                    with netmask, e.g. 192.168.1.0/255.255.255.0 or
                    "192.168.1.0/24".

        Keyword parameters:
        overlap     If true, the criteria will match if it overlaps with the
                    nodecon's network instead of equality.

        Exceptions:
        NameError   Invalid keyword parameter.
        """

        if net:
            try:
                self.network = ipaddress.ip_network(net)
            except NameError:  # pragma: no cover
                raise RuntimeError("IP address/network functions require Python 3.3+.")
        else:
            # ensure self.network is set
            self.network = None

        for k in list(opts.keys()):
            if k == "overlap":
                self.network_overlap = opts[k]
            else:
                raise NameError("Invalid name option: {0}".format(k))

    def set_ip_version(self, version):
        """
        Set the criteria for matching the IP version.

        Parameter:
        version     The address family to match.  (socket.AF_INET for
                    IPv4 or socket.AF_INET6 for IPv6)

        Exceptions:
        ValueError  Invalid address family number.
        """

        if version:
            if not (version == AF_INET or version == AF_INET6):
                raise ValueError(
                    "The address family must be {0} for IPv4 or {1} for IPv6.".
                    format(AF_INET, AF_INET6))

            self.version = version

        else:
            self.version = None
