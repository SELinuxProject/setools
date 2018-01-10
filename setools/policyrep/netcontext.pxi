# Copyright 2014, 2016, Tresys Technology, LLC
# Copyright 2016-2017, Chris PeBenito <pebenito@ieee.org>
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
from collections import namedtuple
from ipaddress import ip_address, ip_network

import warnings
import logging

PortconRange = namedtuple("PortconRange", ["low", "high"])


#
# Netifcon factory functions
#
cdef inline Netifcon netifcon_factory_iter(SELinuxPolicy policy, QpolIteratorItem symbol):
    """Factory function variant for iterating over Netifcon objects."""
    return netifcon_factory(policy, <const qpol_netifcon_t *> symbol.obj)


cdef inline Netifcon netifcon_factory(SELinuxPolicy policy, const qpol_netifcon_t *symbol):
    """Factory function for creating Netifcon objects."""
    r = Netifcon()
    r.policy = policy
    r.handle = symbol
    return r


#
# Nodecon factory functions
#
cdef inline Nodecon nodecon_factory_iter(SELinuxPolicy policy, QpolIteratorItem symbol):
    """Factory function variant for iterating over Nodecon objects."""
    return nodecon_factory(policy, <const qpol_nodecon_t *> symbol.obj)


cdef inline Nodecon nodecon_factory(SELinuxPolicy policy, const qpol_nodecon_t *symbol):
    """Factory function for creating Nodecon objects."""
    r = Nodecon()
    r.policy = policy
    r.handle = symbol
    return r


#
# Portcon factory functions
#
cdef inline Portcon portcon_factory_iter(SELinuxPolicy policy, QpolIteratorItem symbol):
    """Factory function variant for iterating over Portcon objects."""
    return portcon_factory(policy, <const qpol_portcon_t *> symbol.obj)


cdef inline Portcon portcon_factory(SELinuxPolicy policy, const qpol_portcon_t *symbol):
    """Factory function for creating Portcon objects."""
    r = Portcon()
    r.policy = policy
    r.handle = symbol
    return r


#
# Classes
#
cdef class Netifcon(PolicySymbol):

    """A netifcon statement."""

    cdef const qpol_netifcon_t *handle

    def __str__(self):
        return "netifcon {0.netif} {0.context} {0.packet}".format(self)

    def __hash__(self):
        return hash("netifcon|{0.netif}".format(self))

    def __lt__(self, other):
        # this is used by Python sorting functions
        return str(self) < str(other)

    def _eq(self, Netifcon other):
        """Low-level equality check (C pointers)."""
        return self.handle == other.handle

    @property
    def context(self):
        """The context for the interface."""
        cdef const qpol_context_t *ctx
        if qpol_netifcon_get_if_con(self.policy.handle, self.handle, &ctx):
            ex = LowLevelPolicyError("Error reading interface context for netifcon statement: {}".
                                     format(strerror(errno)))
            ex.errno = errno
            raise ex

        return context_factory(self.policy, ctx)

    @property
    def netif(self):
        """The network interface name."""
        cdef const char *name
        if qpol_netifcon_get_name(self.policy.handle, self.handle, &name):
            ex = LowLevelPolicyError("Error reading interface name for netifcon statement: {}".
                                     format(strerror(errno)))
            ex.errno = errno
            raise ex

        return intern(name)

    @property
    def packet(self):
        """The context for the packets."""
        cdef const qpol_context_t *ctx
        if qpol_netifcon_get_msg_con(self.policy.handle, self.handle, &ctx):
            ex = LowLevelPolicyError("Error reading packet context for netifcon statement: {}".
                                     format(strerror(errno)))
            ex.errno = errno
            raise ex

        return context_factory(self.policy, ctx)

    def statement(self):
        return str(self)


class NodeconIPVersion(PolicyEnum):

    """Nodecon IP Version"""

    ipv4 = AF_INET
    ipv6 = AF_INET6


cdef class Nodecon(PolicySymbol):

    """A nodecon statement."""

    cdef const qpol_nodecon_t *handle

    def __str__(self):
        return "nodecon {1} {0.context}".format(self, self.network.with_netmask.replace("/", " "))

    def __hash__(self):
        return hash("nodecon|{}".format(self.network.with_netmask))

    def __eq__(self, other):
        # Libqpol allocates new C objects in the
        # nodecons iterator, so pointer comparison
        # in the PolicySymbol object doesn't work.
        try:
            return (self.network == other.network and
                    self.context == other.context)
        except AttributeError:
            return (str(self) == str(other))

    def _addr(self):
        """Temporary internal function only for as long as addr property exists."""
        cdef uint32_t *a
        cdef unsigned char proto
        cdef char *addr

        addr = <char *> PyMem_Malloc(INET6_ADDRSTRLEN * sizeof(char))
        if not addr:
            raise MemoryError

        if qpol_nodecon_get_addr(self.policy.handle, self.handle, &a, &proto):
            ex = LowLevelPolicyError("Error reading address of nodecon statement: {}".format(
                                     strerror(errno)))
            ex.errno = errno
            raise ex

        # convert network order to string
        if proto == QPOL_IPV4:
            inet_ntop(AF_INET, a, addr, INET6_ADDRSTRLEN)
        else:
            inet_ntop(AF_INET6, a, addr, INET6_ADDRSTRLEN)

        straddress = str(addr)
        PyMem_Free(addr)

        return straddress

    def _eq(self, Nodecon other):
        """Low-level equality check (C pointers)."""
        return self.handle == other.handle

    def _mask(self):
        """Temporary internal function only for as long as mask property exists."""
        cdef uint32_t *m
        cdef unsigned char proto
        cdef char *mask
        mask = <char *> PyMem_Malloc(INET6_ADDRSTRLEN * sizeof(char))
        if not mask:
            raise MemoryError

        if qpol_nodecon_get_mask(self.policy.handle, self.handle, &m, &proto):
            ex = LowLevelPolicyError("Error reading mask of nodecon statement: {}".format(
                                     strerror(errno)))
            ex.errno = errno
            raise ex

        # convert network order to string
        if proto == QPOL_IPV4:
            inet_ntop(AF_INET, m, mask, INET6_ADDRSTRLEN)
        else:
            inet_ntop(AF_INET6, m, mask, INET6_ADDRSTRLEN)

        strmask = str(mask)
        PyMem_Free(mask)

        return strmask

    @property
    def address(self):
        """The network address for the nodecon."""
        warnings.warn("Nodecon.address will be removed in SETools 4.3, please use nodecon.network",
                      DeprecationWarning)
        return self._addr()

    @property
    def context(self):
        """The context for this statement."""
        cdef const qpol_context_t *ctx
        if qpol_nodecon_get_context(self.policy.handle, self.handle, &ctx):
            ex = LowLevelPolicyError("Error reading context for nodecon statement: {}".format(
                                     strerror(errno)))
            ex.errno = errno
            raise ex

        return context_factory(self.policy, ctx)

    @property
    def ip_version(self):
        """
        The IP version for the nodecon (socket.AF_INET or
        socket.AF_INET6).
        """
        cdef unsigned char proto
        if qpol_nodecon_get_protocol(self.policy.handle, self.handle, &proto):
            ex = LowLevelPolicyError("Error reading IP version for nodecon statement: {}".format(
                                     strerror(errno)))
            ex.errno = errno
            raise ex

        if proto == QPOL_IPV4:
            return NodeconIPVersion.ipv4
        else:
            return NodeconIPVersion.ipv6

    @property
    def netmask(self):
        """The network mask for the nodecon."""
        warnings.warn("Nodecon.netmask will be removed in SETools 4.3, please use nodecon.network",
                      DeprecationWarning)
        return self._mask()

    @property
    def network(self):
        """The network for the nodecon."""
        CIDR = 0
        addr = self._addr()
        mask = self._mask()

        # Python 3.4's IPv6Network constructor does not support
        # expanded netmasks, only CIDR numbers. Convert netmask
        # into CIDR.
        # This is Brian Kernighan's method for counting set bits.
        # If the netmask happens to be invalid, this will
        # not detect it.
        int_mask = int(ip_address(mask))
        while int_mask:
            int_mask &= int_mask - 1
            CIDR += 1

        net_with_mask = "{0}/{1}".format(addr, CIDR)
        try:
            # checkpolicy does not verify that no host bits are set,
            # so strict will raise an exception if host bits are set.
            return ip_network(net_with_mask)
        except ValueError as ex:
            log = logging.getLogger(__name__)
            log.warning("Nodecon with network {} {} has host bits set. Analyses may have "
                        "unexpected results.".format(addr, mask))
            return ip_network(net_with_mask, strict=False)

    def statement(self):
        return str(self)


class PortconProtocol(PolicyEnum):

    """A portcon protocol type."""

    tcp = IPPROTO_TCP
    udp = IPPROTO_UDP
    dccp = IPPROTO_DCCP


cdef class Portcon(PolicySymbol):

    """A portcon statement."""

    cdef const qpol_portcon_t *handle

    def __str__(self):
        low, high = self.ports

        if low == high:
            return "portcon {0.protocol} {1} {0.context}".format(self, low)
        else:
            return "portcon {0.protocol} {1}-{2} {0.context}".format(self, low, high)

    def __hash__(self):
            return hash("portcon|{0.protocol}|{1.low}|{1.high}".format(self, self.ports))

    def __lt__(self, other):
        # this is used by Python sorting functions
        return str(self) < str(other)

    def _eq(self, Portcon other):
        """Low-level equality check (C pointers)."""
        return self.handle == other.handle

    @property
    def context(self):
        """The context for this statement."""
        cdef const qpol_context_t *ctx
        if qpol_portcon_get_context(self.policy.handle, self.handle, &ctx):
            ex = LowLevelPolicyError("Error reading context for portcon statement: {}".format(
                                     strerror(errno)))
            ex.errno = errno
            raise ex

        return context_factory(self.policy, ctx)

    @property
    def ports(self):
        """
        The port range for this portcon.

        Return: Tuple(low, high)
        low     The low port of the range.
        high    The high port of the range.
        """
        cdef uint16_t low
        if qpol_portcon_get_low_port(self.policy.handle, self.handle, &low):
            ex = LowLevelPolicyError("Error reading low port for portcon statement: {}".format(
                                     strerror(errno)))
            ex.errno = errno
            raise ex

        cdef uint16_t high
        if qpol_portcon_get_high_port(self.policy.handle, self.handle, &high):
            ex = LowLevelPolicyError("Error reading high port for portcon statement: {}".format(
                                     strerror(errno)))
            ex.errno = errno
            raise ex

        return PortconRange(low, high)

    @property
    def protocol(self):
        """
        The protocol type for the portcon.
        """
        cdef uint8_t proto
        if qpol_portcon_get_protocol(self.policy.handle, self.handle, &proto):
            ex = LowLevelPolicyError("Error reading protocol for portcon statement: {}".format(
                                     strerror(errno)))
            ex.errno = errno
            raise ex

        return PortconProtocol(proto)

    def statement(self):
        return str(self)
