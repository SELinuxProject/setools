# Copyright 2014, Tresys Technology, LLC
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

cdef inline Role role_factory_lookup(SELinuxPolicy policy, str name):
    """Factory function variant for constructing Role objects by name."""

    cdef const qpol_role_t *symbol
    if qpol_policy_get_role_by_name(policy.handle, name.encode(), &symbol):
        raise InvalidRole("{0} is not a valid role".format(name))

    return role_factory(policy, symbol)


cdef inline Role role_factory_iter(SELinuxPolicy policy, QpolIteratorItem symbol):
    """Factory function variant for iterating over Role objects."""
    return role_factory(policy, <const qpol_role_t *> symbol.obj)


cdef inline Role role_factory(SELinuxPolicy policy, const qpol_role_t *symbol):
    """Factory function for creating Role objects."""
    r = Role()
    r.policy = policy
    r.handle = symbol
    return r


cdef class BaseRole(PolicySymbol):

    """Role/role attribute base class."""

    def expand(self):
        raise NotImplementedError

    def types(self):
        raise NotImplementedError


cdef class Role(BaseRole):

    """A role."""

    cdef const qpol_role_t *handle

    def __str__(self):
        cdef const char *name

        if qpol_role_get_name(self.policy.handle, self.handle, &name):
            ex = LowLevelPolicyError("Error reading role name: {}".format(strerror(errno)))
            ex.errno = errno
            raise ex

        return name

    def _eq(self, Role other):
        """Low-level equality check (C pointers)."""
        return self.handle == other.handle

    def dominated_roles(self):
        """The roles that this role dominates."""
        cdef qpol_iterator_t *iter
        if qpol_role_get_dominate_iter(self.policy.handle, self.handle, &iter):
            raise MemoryError

        return qpol_iterator_factory(self.policy, iter, role_factory_iter)

    def expand(self):
        """Generator that expands this into its member roles."""
        yield self

    def types(self):
        """Generator which yields the role's set of types."""
        cdef qpol_iterator_t *iter
        if qpol_role_get_type_iter(self.policy.handle, self.handle, &iter):
            raise MemoryError

        return qpol_iterator_factory(self.policy, iter, type_factory_iter)

    def statement(self):
        types = list(str(t) for t in self.types())
        stmt = "role {0}".format(self)
        if types:
            if (len(types) > 1):
                stmt += " types {{ {0} }}".format(' '.join(types))
            else:
                stmt += " types {0}".format(types[0])
        stmt += ";"
        return stmt


cdef class RoleAttribute(BaseRole):

    """A role attribute."""

    pass
