# Copyright 2014-2015, Tresys Technology, LLC
# Copyright 2017, Chris PeBenito <pebenito@ieee.org>
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

#
# Factory functions
#
cdef inline PolicyCapability polcap_factory_iter(SELinuxPolicy policy, QpolIteratorItem symbol):
    """Factory function variant for iterating over PolicyCapability objects."""
    return polcap_factory(policy, <const qpol_polcap_t *> symbol.obj)


cdef inline PolicyCapability polcap_factory(SELinuxPolicy policy, const qpol_polcap_t *symbol):
    """Factory function for creating PolicyCapability objects."""
    r = PolicyCapability()
    r.policy = policy
    r.handle = symbol
    return r


#
# Class
#
cdef class PolicyCapability(PolicySymbol):

    """A policy capability."""

    cdef const qpol_polcap_t *handle

    def __str__(self):
        cdef const char *name

        if qpol_polcap_get_name(self.policy.handle, self.handle, &name):
            ex = LowLevelPolicyError("Error reading polcap name: {}".format(strerror(errno)))
            ex.errno = errno
            raise ex

        return intern(name)

    def _eq(self, PolicyCapability other):
        """Low-level equality check (C pointers)."""
        return self.handle == other.handle

    def statement(self):
        return "policycap {0};".format(self)
