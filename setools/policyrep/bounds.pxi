# Copyright 2016, Tresys Technology, LLC
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

#
# Factory functions
#
cdef inline Bounds bounds_factory_iter(SELinuxPolicy policy, QpolIteratorItem symbol):
    """Factory function variant for iterating over Bounds objects."""
    return bounds_factory(policy, <const qpol_typebounds_t *> symbol.obj)


cdef inline Bounds bounds_factory(SELinuxPolicy policy, const qpol_typebounds_t *symbol):
    """Factory function for creating Bounds objects."""
    r = Bounds()
    r.policy = policy
    r.handle = symbol
    return r


#def validate_ruletype(t):
#    """Validate *bounds rule types."""
#    try:
#        return BoundsRuletype.lookup(t)
#    except KeyError as ex:
#        raise exception.InvalidBoundsType("{0} is not a valid *bounds rule type.".format(t)) from ex


#
# Classes
#
class BoundsRuletype(PolicyEnum):

    """Enumeration of *bounds rule types."""

    typebounds = 1


cdef class Bounds(PolicySymbol):

    """A typebounds statement."""

    cdef const qpol_typebounds_t *handle
    cdef readonly object ruletype

    def __init__(self):
        self.ruletype = BoundsRuletype.typebounds

    def __str__(self):
        return "{0.ruletype} {0.parent} {0.child};".format(self)

    def __hash__(self):
        return hash("{0.ruletype}|{0.child};".format(self))

    def __lt__(self, other):
        # this is used by Python sorting functions
        return str(self) < str(other)

    def _eq(self, Bounds other):
        """Low-level equality check (C pointers)."""
        return self.handle == other.handle

    # TODO: look at qpol code to see if these functions
    # can be converted to return symbols rather than names
    @property
    def parent(self):
        cdef const char *name
        if qpol_typebounds_get_parent_name(self.policy.handle, self.handle, &name):
            raise RuntimeError("Could not get parent name")

        return self.policy.lookup_type(name)

    @property
    def child(self):
        pass
        cdef const char *name
        if qpol_typebounds_get_child_name(self.policy.handle, self.handle, &name):
            raise RuntimeError("Could not get child name")

        return self.policy.lookup_type(name)
