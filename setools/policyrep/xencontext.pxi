# Copyright 2017-2018, Chris PeBenito <pebenito@ieee.org>
# Derived from netcontext.py
#
# SPDX-License-Identifier: LGPL-2.1-only
#

@dataclasses.dataclass(eq=True, order=True, frozen=True)
class IomemconRange:

    """A range of Xen IO memory ranges"""

    low: int
    high: int

    MIN: dataclasses.ClassVar[int] = dataclasses.field(init=False, default=0x0001)
    MAX: dataclasses.ClassVar[int] = dataclasses.field(init=False, default=0xffff)

    def __post_init__(self):
        if self.low < IomemconRange.MIN or self.high < IomemconRange.MIN:
            raise ValueError(
                f"Memory address must be >= {IomemconRange.MIN}: {self.low}-{self.high}")

        if self.low > IomemconRange.MAX or self.high > IomemconRange.MAX:
            raise ValueError(
                f"Memory address must be <= {IomemconRange.MAX}: {self.low}-{self.high}")

        if self.low > self.high:
            raise ValueError(
                f"The low mem addr must be smaller than the high mem addr: {self.low}-{self.high}")


@dataclasses.dataclass(eq=True, order=True, frozen=True)
class IoportconRange:

    """A range of Xen IO ports"""

    low: int
    high: int

    MIN: dataclasses.ClassVar[int] = dataclasses.field(init=False, default=0x0001)
    MAX: dataclasses.ClassVar[int] = dataclasses.field(init=False, default=0xffff)

    def __post_init__(self):
        if self.low < IoportconRange.MIN or self.high < IoportconRange.MIN:
            raise ValueError(
                f"Port numbers must be >= {IoportconRange.MIN}: {self.low}-{self.high}")

        if self.low > IoportconRange.MAX or self.high > IoportconRange.MAX:
            raise ValueError(
                f"Port numbers must be <= {IoportconRange.MAX}: {self.low}-{self.high}")

        if self.low > self.high:
            raise ValueError("The low port must be smaller than the high port: "
                f"{self.low}-{self.high}")

#
# Classes
#
cdef class Devicetreecon(Ocontext):

    """A devicetreecon statement."""

    cdef readonly str path

    @staticmethod
    cdef inline Devicetreecon factory(SELinuxPolicy policy, sepol.ocontext_t *symbol):
        """Factory function for creating Devicetreecon objects."""
        cdef Devicetreecon d = Devicetreecon.__new__(Devicetreecon)
        d.policy = policy
        d.key = <uintptr_t>symbol
        d.path = intern(symbol.u.name)
        d.context = Context.factory(policy, symbol.context)
        return d

    def statement(self):
        return f"devicetreecon {self.path} {self.context}"


cdef class Iomemcon(Ocontext):

    """A iomemcon statement."""

    cdef readonly object addr

    @staticmethod
    cdef inline Iomemcon factory(SELinuxPolicy policy, sepol.ocontext_t *symbol):
        """Factory function for creating Iomemcon objects."""
        cdef Iomemcon i = Iomemcon.__new__(Iomemcon)
        i.policy = policy
        i.key = <uintptr_t>symbol
        i.addr = IomemconRange(symbol.u.iomem.low_iomem, symbol.u.iomem.high_iomem)
        i.context = Context.factory(policy, symbol.context)
        return i

    def statement(self):
        low, high = self.addr.low, self.addr.high

        if low == high:
            return "iomemcon {low} {self.context1}"
        else:
            return "iomemcon {low}-{high} {self.context}"


cdef class Ioportcon(Ocontext):

    """A ioportcon statement."""

    cdef readonly object ports

    @staticmethod
    cdef inline Ioportcon factory(SELinuxPolicy policy, sepol.ocontext_t *symbol):
        """Factory function for creating Ioportcon objects."""
        cdef Ioportcon i = Ioportcon.__new__(Ioportcon)
        i.policy = policy
        i.key = <uintptr_t>symbol
        i.ports = IoportconRange(symbol.u.ioport.low_ioport, symbol.u.ioport.high_ioport)
        i.context = Context.factory(policy, symbol.context)
        return i

    def statement(self):
        low, high = self.ports.low, self.ports.high

        if low == high:
            return "ioportcon {low} {self.context}"
        else:
            return "ioportcon {low}-{high} {self.context}"


cdef class Pcidevicecon(Ocontext):

    """A pcidevicecon statement."""

    cdef readonly object device

    @staticmethod
    cdef inline Pcidevicecon factory(SELinuxPolicy policy, sepol.ocontext_t *symbol):
        """Factory function for creating Pcidevicecon objects."""
        cdef Pcidevicecon p = Pcidevicecon.__new__(Pcidevicecon)
        p.policy = policy
        p.key = <uintptr_t>symbol
        p.device = symbol.u.device
        p.context = Context.factory(policy, symbol.context)
        return p

    def statement(self):
        return f"pcidevicecon {self.device} {self.context}"


cdef class Pirqcon(Ocontext):

    """A pirqcon statement."""

    cdef readonly object irq

    @staticmethod
    cdef inline Pirqcon factory(SELinuxPolicy policy, sepol.ocontext_t *symbol):
        """Factory function for creating Pirqcon objects."""
        cdef Pirqcon p = Pirqcon.__new__(Pirqcon)
        p.policy = policy
        p.key = <uintptr_t>symbol
        p.irq = symbol.u.pirq
        p.context = Context.factory(policy, symbol.context)
        return p

    def statement(self):
        return f"pirqcon {self.irq} {self.context}"


#
# Iterators
#
cdef class DevicetreeconIterator(OcontextIterator):

    """Iterator for devicetreecon statements in the policy."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.ocontext_t *head):
        """Factory function for creating Devicetreecon iterators."""
        i = DevicetreeconIterator()
        i.policy = policy
        i.head = i.curr = head
        return i

    def __next__(self):
        super().__next__()
        return Devicetreecon.factory(self.policy, self.ocon)


cdef class IomemconIterator(OcontextIterator):

    """Iterator for iomemcon statements in the policy."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.ocontext_t *head):
        """Factory function for creating Iomemcon iterators."""
        i = IomemconIterator()
        i.policy = policy
        i.head = i.curr = head
        return i

    def __next__(self):
        super().__next__()
        return Iomemcon.factory(self.policy, self.ocon)


cdef class IoportconIterator(OcontextIterator):

    """Iterator for ioportcon statements in the policy."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.ocontext_t *head):
        """Factory function for creating Ioportcon iterators."""
        i = IoportconIterator()
        i.policy = policy
        i.head = i.curr = head
        return i

    def __next__(self):
        super().__next__()
        return Ioportcon.factory(self.policy, self.ocon)


cdef class PcideviceconIterator(OcontextIterator):

    """Iterator for pcidevicecon statements in the policy."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.ocontext_t *head):
        """Factory function for creating Pcidevicecon iterators."""
        i = PcideviceconIterator()
        i.policy = policy
        i.head = i.curr = head
        return i

    def __next__(self):
        super().__next__()
        return Pcidevicecon.factory(self.policy, self.ocon)


cdef class PirqconIterator(OcontextIterator):

    """Iterator for pirqcon statements in the policy."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.ocontext_t *head):
        """Factory function for creating Pirqcon iterators."""
        i = PirqconIterator()
        i.policy = policy
        i.head = i.curr = head
        return i

    def __next__(self):
        super().__next__()
        return Pirqcon.factory(self.policy, self.ocon)
