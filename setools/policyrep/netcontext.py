# Copyright 2014, Tresys Technology, LLC
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
import socket
from collections import namedtuple

from . import qpol
from . import symbol
from . import context

port_range = namedtuple("port_range", ["low", "high"])


def netifcon_factory(policy, name):
    """Factory function for creating netifcon objects."""

    if not isinstance(name, qpol.qpol_netifcon_t):
        raise NotImplementedError

    return Netifcon(policy, name)


def nodecon_factory(policy, name):
    """Factory function for creating nodecon objects."""

    if not isinstance(name, qpol.qpol_nodecon_t):
        raise NotImplementedError

    return Nodecon(policy, name)


def portcon_factory(policy, name):
    """Factory function for creating portcon objects."""

    if not isinstance(name, qpol.qpol_portcon_t):
        raise NotImplementedError

    return Portcon(policy, name)


class NetContext(symbol.PolicySymbol):

    """Base class for in-policy network labeling rules."""

    def __str__(self):
        raise NotImplementedError

    @property
    def context(self):
        """The context for this statement."""
        return context.context_factory(self.policy, self.qpol_symbol.context(self.policy))

    def statement(self):
        return str(self)


class Netifcon(NetContext):

    """A netifcon statement."""

    def __str__(self):
        return "netifcon {0.netif} {0.context} {0.packet}".format(self)

    @property
    def netif(self):
        """The network interface name."""
        return self.qpol_symbol.name(self.policy)

    @property
    def context(self):
        """The context for the interface."""
        return context.context_factory(self.policy, self.qpol_symbol.if_con(self.policy))

    @property
    def packet(self):
        """The context for the packets."""
        return context.context_factory(self.policy, self.qpol_symbol.msg_con(self.policy))


class Nodecon(NetContext):

    """A nodecon statement."""

    def __str__(self):
        return "nodecon {0.address} {0.netmask} {0.context}".format(self)

    def __eq__(self, other):
        # Libqpol allocates new C objects in the
        # nodecons iterator, so pointer comparison
        # in the PolicySymbol object doesn't work.
        try:
            return (self.address == other.address and
                    self.netmask == other.netmask and
                    self.context == other.context)
        except AttributeError:
            return (str(self) == str(other))

    @property
    def ip_version(self):
        """
        The IP version for the nodecon (socket.AF_INET or
        socket.AF_INET6).
        """
        return self.qpol_symbol.protocol(self.policy)

    @property
    def address(self):
        """The network address for the nodecon."""
        return self.qpol_symbol.addr(self.policy)

    @property
    def netmask(self):
        """The network mask for the nodecon."""
        return self.qpol_symbol.mask(self.policy)


class Portcon(NetContext):

    """A portcon statement."""

    _proto_to_text = {socket.IPPROTO_TCP: 'tcp',
                      socket.IPPROTO_UDP: 'udp'}

    def __str__(self):
        low, high = self.ports
        proto = self._proto_to_text[self.protocol]

        if low == high:
            return "portcon {0} {1} {2}".format(proto, low, self.context)
        else:
            return "portcon {0} {1}-{2} {3}".format(proto, low, high, self.context)

    @property
    def protocol(self):
        """
        The protocol number for the portcon (socket.IPPROTO_TCP
        or socket.IPPROTO_UDP).
        """
        return self.qpol_symbol.protocol(self.policy)

    @property
    def ports(self):
        """
        The port range for this portcon.

        Return: Tuple(low, high)
        low     The low port of the range.
        high    The high port of the range.
        """
        low = self.qpol_symbol.low_port(self.policy)
        high = self.qpol_symbol.high_port(self.policy)
        return port_range(low, high)
