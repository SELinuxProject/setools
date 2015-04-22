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
from . import qpol
from . import symbol


def polcap_factory(policy, name):
    """Factory function for creating policy capability objects."""

    if isinstance(name, PolicyCapability):
        assert name.policy == policy
        return name
    elif isinstance(name, qpol.qpol_polcap_t):
        return PolicyCapability(policy, name)
    else:
        raise TypeError("Policy capabilities cannot be looked up.")


class PolicyCapability(symbol.PolicySymbol):

    """A policy capability."""

    def statement(self):
        return "policycap {0};".format(self)
