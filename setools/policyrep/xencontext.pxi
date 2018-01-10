# Copyright 2017, Chris PeBenito <pebenito@ieee.org>
# Derived from netcontext.py
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

IomemconRange = namedtuple("IomemconRange", ["low", "high"])
IoportconRange = namedtuple("IoportconRange", ["low", "high"])


#
# Devicetreecon factory functions
#
cdef inline Devicetreecon devicetreecon_factory_iter(SELinuxPolicy policy, QpolIteratorItem symbol):
    """Factory function variant for iterating over Devicetreecon objects."""
    return devicetreecon_factory(policy, <const qpol_devicetreecon_t *> symbol.obj)


cdef inline Devicetreecon devicetreecon_factory(SELinuxPolicy policy, const qpol_devicetreecon_t *symbol):
    """Factory function for creating Devicetreecon objects."""
    r = Devicetreecon()
    r.policy = policy
    r.handle = symbol
    return r


#
# Iomemcon factory functions
#
cdef inline Iomemcon iomemcon_factory_iter(SELinuxPolicy policy, QpolIteratorItem symbol):
    """Factory function variant for iterating over Iomemcon objects."""
    return iomemcon_factory(policy, <const qpol_iomemcon_t *> symbol.obj)


cdef inline Iomemcon iomemcon_factory(SELinuxPolicy policy, const qpol_iomemcon_t *symbol):
    """Factory function for creating Iomemcon objects."""
    r = Iomemcon()
    r.policy = policy
    r.handle = symbol
    return r


#
# Ioportcon factory functions
#
cdef inline Ioportcon ioportcon_factory_iter(SELinuxPolicy policy, QpolIteratorItem symbol):
    """Factory function variant for iterating over Ioportcon objects."""
    return ioportcon_factory(policy, <const qpol_ioportcon_t *> symbol.obj)


cdef inline Ioportcon ioportcon_factory(SELinuxPolicy policy, const qpol_ioportcon_t *symbol):
    """Factory function for creating Ioportcon objects."""
    r = Ioportcon()
    r.policy = policy
    r.handle = symbol
    return r


#
# Pcidevicecon factory functions
#
cdef inline Pcidevicecon pcidevicecon_factory_iter(SELinuxPolicy policy, QpolIteratorItem symbol):
    """Factory function variant for iterating over Pcidevicecon objects."""
    return pcidevicecon_factory(policy, <const qpol_pcidevicecon_t *> symbol.obj)


cdef inline Pcidevicecon pcidevicecon_factory(SELinuxPolicy policy, const qpol_pcidevicecon_t *symbol):
    """Factory function for creating Pcidevicecon objects."""
    r = Pcidevicecon()
    r.policy = policy
    r.handle = symbol
    return r


#
# Pirqcon factory functions
#
cdef inline Pirqcon pirqcon_factory_iter(SELinuxPolicy policy, QpolIteratorItem symbol):
    """Factory function variant for iterating over Pirqcon objects."""
    return pirqcon_factory(policy, <const qpol_pirqcon_t *> symbol.obj)


cdef inline Pirqcon pirqcon_factory(SELinuxPolicy policy, const qpol_pirqcon_t *symbol):
    """Factory function for creating Pirqcon objects."""
    r = Pirqcon()
    r.policy = policy
    r.handle = symbol
    return r

#
# Classes
#
cdef class Devicetreecon(PolicySymbol):

    """A devicetreecon statement."""

    cdef const qpol_devicetreecon_t *handle

    def __str__(self):
        return "devicetreecon {0.path} {0.context}".format(self)

    def _eq(self, Devicetreecon other):
        """Low-level equality check (C pointers)."""
        return self.handle == other.handle

    @property
    def context(self):
        """The context for this statement."""
        cdef const qpol_context_t *ctx
        if qpol_devicetreecon_get_context(self.policy.handle, self.handle, &ctx):
            ex = LowLevelPolicyError("Error reading context for devicetreecon statement: {}".format(
                                     strerror(errno)))
            ex.errno = errno
            raise ex

        return context_factory(self.policy, ctx)

    @property
    def path(self):
        """
        The path for this devicetreecon.

        Return: The device path name.
        """
        cdef char *path
        if qpol_devicetreecon_get_path(self.policy.handle, self.handle, &path):
            ex = LowLevelPolicyError("Error reading path for devicetreecon statement: {}".format(
                                     strerror(errno)))
            ex.errno = errno
            raise ex

        return intern(path)

    def statement(self):
        return str(self)


cdef class Iomemcon(PolicySymbol):

    """A iomemcon statement."""

    cdef const qpol_iomemcon_t *handle

    def __str__(self):
        low, high = self.addr

        if low == high:
            return "iomemcon {0} {1}".format(low, self.context)
        else:
            return "iomemcon {0}-{1} {2}".format(low, high, self.context)

    def _eq(self, Iomemcon other):
        """Low-level equality check (C pointers)."""
        return self.handle == other.handle

    @property
    def addr(self):
        """
        The memory range for this iomemcon.

        Return: Tuple(low, high)
        low     The low memory of the range.
        high    The high memory of the range.
        """
        cdef uint64_t low = 0
        if qpol_iomemcon_get_low_addr(self.policy.handle, self.handle, &low):
            ex = LowLevelPolicyError("Error reading low addr for iomemcon statement: {}".format(
                                     strerror(errno)))
            ex.errno = errno
            raise ex

        cdef uint64_t high = 0
        if qpol_iomemcon_get_high_addr(self.policy.handle, self.handle, &high):
            ex = LowLevelPolicyError("Error reading high addr for iomemcon statement: {}".format(
                                     strerror(errno)))
            ex.errno = errno
            raise ex

        return IomemconRange(low, high)

    @property
    def context(self):
        """The context for this statement."""
        cdef const qpol_context_t *ctx
        if qpol_iomemcon_get_context(self.policy.handle, self.handle, &ctx):
            ex = LowLevelPolicyError("Error reading context for iomemcon statement: {}".format(
                                     strerror(errno)))
            ex.errno = errno
            raise ex

        return context_factory(self.policy, ctx)

    def statement(self):
        return str(self)


cdef class Ioportcon(PolicySymbol):

    """A ioportcon statement."""

    cdef const qpol_ioportcon_t *handle

    def __str__(self):
        low, high = self.ports

        if low == high:
            return "ioportcon {0} {1}".format(low, self.context)
        else:
            return "ioportcon {0}-{1} {2}".format(low, high, self.context)

    def _eq(self, Ioportcon other):
        """Low-level equality check (C pointers)."""
        return self.handle == other.handle

    @property
    def context(self):
        """The context for this statement."""
        cdef const qpol_context_t *ctx
        if qpol_ioportcon_get_context(self.policy.handle, self.handle, &ctx):
            ex = LowLevelPolicyError("Error reading context for ioportcon statement: {}".format(
                                     strerror(errno)))
            ex.errno = errno
            raise ex

        return context_factory(self.policy, ctx)

    @property
    def ports(self):
        """
        The port range for this ioportcon.

        Return: Tuple(low, high)
        low     The low port of the range.
        high    The high port of the range.
        """
        cdef uint32_t low
        if qpol_ioportcon_get_low_port(self.policy.handle, self.handle, &low):
            ex = LowLevelPolicyError("Error reading low port for ioportcon statement: {}".format(
                                     strerror(errno)))
            ex.errno = errno
            raise ex

        cdef uint32_t high
        if qpol_ioportcon_get_high_port(self.policy.handle, self.handle, &high):
            ex = LowLevelPolicyError("Error reading high port for ioportcon statement: {}".format(
                                     strerror(errno)))
            ex.errno = errno
            raise ex

        return IoportconRange(low, high)

    def statement(self):
        return str(self)


cdef class Pcidevicecon(PolicySymbol):

    """A pcidevicecon statement."""

    cdef const qpol_pcidevicecon_t *handle

    def __str__(self):
        return "pcidevicecon {0.device} {0.context}".format(self)

    def _eq(self, Pcidevicecon other):
        """Low-level equality check (C pointers)."""
        return self.handle == other.handle

    @property
    def context(self):
        """The context for this statement."""
        cdef const qpol_context_t *ctx
        if qpol_pcidevicecon_get_context(self.policy.handle, self.handle, &ctx):
            ex = LowLevelPolicyError("Error reading context for pcidevicecon statement: {}".format(
                                     strerror(errno)))
            ex.errno = errno
            raise ex

        return context_factory(self.policy, ctx)

    @property
    def device(self):
        """
        The device for this pcidevicecon.

        Return: The PCI device ID.
        """
        cdef uint32_t device
        if qpol_pcidevicecon_get_device(self.policy.handle, self.handle, &device):
            ex = LowLevelPolicyError("Error reading device for pcidevicecon statement: {}".format(
                                     strerror(errno)))
            ex.errno = errno
            raise ex

        return device

    def statement(self):
        return str(self)


cdef class Pirqcon(PolicySymbol):

    """A pirqcon statement."""

    cdef const qpol_pirqcon_t *handle

    def __str__(self):
        return "pirqcon {0.irq} {0.context}".format(self)

    def _eq(self, Pirqcon other):
        """Low-level equality check (C pointers)."""
        return self.handle == other.handle

    @property
    def context(self):
        """The context for this statement."""
        cdef const qpol_context_t *ctx
        if qpol_pirqcon_get_context(self.policy.handle, self.handle, &ctx):
            ex = LowLevelPolicyError("Error reading context for pirqcon statement: {}".format(
                                     strerror(errno)))
            ex.errno = errno
            raise ex

        return context_factory(self.policy, ctx)

    @property
    def irq(self):
        """
        The irq for this pirqcon.

        Return: The irq.
        """
        cdef uint16_t irq
        if qpol_pirqcon_get_irq(self.policy.handle, self.handle, &irq):
            ex = LowLevelPolicyError("Error reading irq for pirqcon statement: {}".format(
                                     strerror(errno)))
            ex.errno = errno
            raise ex

        return irq

    def statement(self):
        return str(self)
