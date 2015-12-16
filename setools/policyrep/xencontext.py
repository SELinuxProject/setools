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

from . import qpol
from . import symbol
from . import context

addr_range = namedtuple("memory_range", ["low", "high"])
port_range = namedtuple("port_range", ["low", "high"])
device_id = namedtuple("device_id", ["low"])
pirq = namedtuple("irq", ["low"])
dev_path = namedtuple("dev_path", ["path"])

def iomemcon_factory(policy, name):
    """Factory function for creating iomemcon objects."""

    if not isinstance(name, qpol.qpol_iomemcon_t):
        raise NotImplementedError

    return Iomemcon(policy, name)


def ioportcon_factory(policy, name):
    """Factory function for creating ioportcon objects."""

    if not isinstance(name, qpol.qpol_ioportcon_t):
        raise NotImplementedError

    return Ioportcon(policy, name)


def pirqcon_factory(policy, name):
    """Factory function for creating pirqcon objects."""

    if not isinstance(name, qpol.qpol_pirqcon_t):
        raise NotImplementedError

    return Pirqcon(policy, name)


def pcidevicecon_factory(policy, name):
    """Factory function for creating pcidevicecon objects."""

    if not isinstance(name, qpol.qpol_pcidevicecon_t):
        raise NotImplementedError

    return Pcidevicecon(policy, name)


def devicetreecon_factory(policy, name):
    """Factory function for creating devicetreecon objects."""

    if not isinstance(name, qpol.qpol_devicetreecon_t):
        raise NotImplementedError

    return Devicetreecon(policy, name)


class XenContext(symbol.PolicySymbol):

    """Base class for in-policy xen labeling rules."""

    def __str__(self):
        raise NotImplementedError

    @property
    def context(self):
        """The context for this statement."""
        return context.context_factory(self.policy, self.qpol_symbol.context(self.policy))

    def statement(self):
        return str(self)


class Iomemcon(XenContext):

    """A iomemcon statement."""

    def __str__(self):
        low, high = self.mem_addr

        if low == high:
            return "iomemcon {0} {1}".format(low, self.context)
        else:
            return "iomemcon {0}-{1} {2}".format(low, high, self.context)

    @property
    def mem_addr(self):
        """
        The memory range for this iomemcon.

        Return: Tuple(low, high)
        low     The low memory of the range.
        high    The high memory of the range.
        """
        low = self.qpol_symbol.low_addr(self.policy)
        high = self.qpol_symbol.high_addr(self.policy)
        return addr_range(low, high)

class Ioportcon(XenContext):

    """A ioportcon statement."""

    def __str__(self):
        low, high = self.ports

        if low == high:
            return "ioportcon {0} {1}".format(low, self.context)
        else:
            return "ioportcon {0}-{1} {2}".format(low, high, self.context)

    @property
    def ports(self):
        """
        The port range for this ioportcon.

        Return: Tuple(low, high)
        low     The low port of the range.
        high    The high port of the range.
        """

        low = self.qpol_symbol.low_port(self.policy)
        high = self.qpol_symbol.high_port(self.policy)
        return port_range(low, high)

class Pcidevicecon(XenContext):

    """A pcidevicecon statement."""

    def __str__(self):
        device_id = self.device

        return "pcidevicecon {0} {1}".format(device_id, self.context)

    @property
    def device(self):
        """
        The device for this pcidevicecon.

        Return: Tuple(low)
        low    The PCI device ID.
        """
        device_id = self.qpol_symbol.device(self.policy)
        return device_id

class Pirqcon(XenContext):

    """A pirqcon statement."""

    def __str__(self):
        pirq = self.irq

        return "pirqcon {0} {1}".format(pirq, self.context)

    @property
    def irq(self):
        """
        The irq for this pirqcon.

        Return: Tuple(low)
        low     The irq.
        """
        pirq = self.qpol_symbol.irq(self.policy)
        return pirq

class Devicetreecon(XenContext):

    """A devicetreecon statement."""

    def __str__(self):
        dev_path = self.path

        return "devicetreecon {0} {1}".format(dev_path, self.context)

    @property
    def path(self):
        """
        The path for this devicetreecon.

        Return: Tuple(path)
        path    The device path name.
        """
        dev_path = self.qpol_symbol.path(self.policy)
        return dev_path
