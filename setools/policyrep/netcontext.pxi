# Copyright 2014, 2016, Tresys Technology, LLC
# Copyright 2016-2018, Chris PeBenito <pebenito@ieee.org>
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
# Classes
#
cdef class Netifcon(Ocontext):

    """A netifcon statement."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.ocontext_t *symbol):
        """Factory function for creating Netifcon objects."""
        n = Netifcon()
        n.policy = policy
        n.handle = symbol
        return n

    def __str__(self):
        return "netifcon {0.netif} {0.context} {0.packet}".format(self)

    def __hash__(self):
        return hash("netifcon|{0.netif}".format(self))

    def __lt__(self, other):
        # this is used by Python sorting functions
        return str(self) < str(other)

    @property
    def netif(self):
        """The network interface name."""
        return intern(self.handle.u.name)

    @property
    def packet(self):
        """The context for the packets."""
        return context_factory(self.policy, <const qpol_context_t *> &self.handle.context[1])


class NodeconIPVersion(PolicyEnum):

    """Nodecon IP Version"""

    ipv4 = AF_INET
    ipv6 = AF_INET6


cdef class Nodecon(Ocontext):

    """A nodecon statement."""

    cdef readonly object ip_version

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.ocontext_t *symbol, ip_version):
        """Factory function for creating Nodecon objects."""
        n = Nodecon()
        n.policy = policy
        n.handle = symbol
        n.ip_version = ip_version
        return n

    def __str__(self):
        return "nodecon {1} {0.context}".format(self, self.network.with_netmask.replace("/", " "))

    def __hash__(self):
        return hash("nodecon|{}".format(self.network.with_netmask))

    def __lt__(self, other):
        # this is used by Python sorting functions
        return str(self) < str(other)

    def _addr(self):
        """Temporary internal function only for as long as addr property exists."""
        cdef uint32_t *a
        cdef unsigned char proto
        cdef char *addr

        addr = <char *> PyMem_Malloc(INET6_ADDRSTRLEN * sizeof(char))
        if not addr:
            raise MemoryError

        # convert network order to string
        if self.ip_version == NodeconIPVersion.ipv4:
            inet_ntop(AF_INET, &self.handle.u.node.addr, addr, INET6_ADDRSTRLEN)
        else:
            inet_ntop(AF_INET6, &self.handle.u.node6.addr, addr, INET6_ADDRSTRLEN)

        straddress = str(addr)
        PyMem_Free(addr)

        return straddress

    def _mask(self):
        """Temporary internal function only for as long as mask property exists."""
        cdef uint32_t *m
        cdef unsigned char proto
        cdef char *mask
        mask = <char *> PyMem_Malloc(INET6_ADDRSTRLEN * sizeof(char))
        if not mask:
            raise MemoryError

        # convert network order to string
        if self.ip_version == NodeconIPVersion.ipv4:
            inet_ntop(AF_INET, &self.handle.u.node.mask, mask, INET6_ADDRSTRLEN)
        else:
            inet_ntop(AF_INET6, &self.handle.u.node6.mask, mask, INET6_ADDRSTRLEN)

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


class PortconProtocol(PolicyEnum):

    """A portcon protocol type."""

    tcp = IPPROTO_TCP
    udp = IPPROTO_UDP
    dccp = IPPROTO_DCCP


cdef class Portcon(Ocontext):

    """A portcon statement."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.ocontext_t *symbol):
        """Factory function for creating Portcon objects."""
        p = Portcon()
        p.policy = policy
        p.handle = symbol
        return p

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

    @property
    def ports(self):
        """
        The port range for this portcon.

        Return: Tuple(low, high)
        low     The low port of the range.
        high    The high port of the range.
        """
        return PortconRange(self.handle.u.port.low_port, self.handle.u.port.high_port)

    @property
    def protocol(self):
        """
        The protocol type for the portcon.
        """
        return PortconProtocol(self.handle.u.port.protocol)


#
# Iterators
#
cdef class NetifconIterator(OcontextIterator):

    """Iterator for netifcon statements in the policy."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.ocontext_t *head):
        """Factory function for creating Netifcon iterators."""
        i = NetifconIterator()
        i.policy = policy
        i.head = i.curr = head
        return i

    def __next__(self):
        super().__next__()
        return Netifcon.factory(self.policy, self.ocon)


cdef class NodeconIterator(OcontextIterator):

    """Iterator for nodecon statements in the policy."""

    cdef object ip_version

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.ocontext_t *head, ip_version):
        """Factory function for creating Nodecon iterators."""
        i = NodeconIterator()
        i.policy = policy
        i.head = i.curr = head
        i.ip_version = ip_version
        return i

    def __next__(self):
        super().__next__()
        return Nodecon.factory(self.policy, self.ocon, self.ip_version)


cdef class PortconIterator(OcontextIterator):

    """Iterator for portcon statements in the policy."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.ocontext_t *head):
        """Factory function for creating Portcon iterators."""
        i = PortconIterator()
        i.policy = policy
        i.head = i.curr = head
        return i

    def __next__(self):
        super().__next__()
        return Portcon.factory(self.policy, self.ocon)
