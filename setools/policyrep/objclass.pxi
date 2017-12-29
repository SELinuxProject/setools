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
# Commons factory functions
#
cdef inline Common common_factory_lookup(SELinuxPolicy policy, str name):
    """Factory function variant for constructing Common objects by name."""

    cdef const qpol_common_t *symbol
    if qpol_policy_get_common_by_name(policy.handle, name.encode(), &symbol):
        raise InvalidCommon("{0} is not a valid common".format(name))

    return common_factory(policy, symbol)


cdef inline Common common_factory_iter(SELinuxPolicy policy, QpolIteratorItem symbol):
    """Factory function variant for iterating over Common objects."""
    return common_factory(policy, <const qpol_common_t *> symbol.obj)


cdef inline Common common_factory(SELinuxPolicy policy, const qpol_common_t *symbol):
    """Factory function for creating Common objects."""
    r = Common()
    r.policy = policy
    r.handle = symbol
    return r

#
# Object class factory functions
#
cdef inline ObjClass class_factory_lookup(SELinuxPolicy policy, str name):
    """Factory function variant for constructing ObjClass objects by name."""

    cdef const qpol_class_t *symbol
    if qpol_policy_get_class_by_name(policy.handle, name.encode(), &symbol):
        raise InvalidClass("{0} is not a valid class".format(name))

    return class_factory(policy, symbol)


cdef inline ObjClass class_factory_iter(SELinuxPolicy policy, QpolIteratorItem symbol):
    """Factory function variant for iterating over ObjClass objects."""
    return class_factory(policy, <const qpol_class_t *> symbol.obj)


cdef inline ObjClass class_factory(SELinuxPolicy policy, const qpol_class_t *symbol):
    """Factory function for creating ObjClass objects."""
    r = ObjClass()
    r.policy = policy
    r.handle = symbol
    return r

#
# Classes
#
cdef class Common(PolicySymbol):

    """A common permission set."""

    cdef const qpol_common_t *handle

    def __str__(self):
        cdef const char *name

        if qpol_common_get_name(self.policy.handle, self.handle, &name):
            ex = LowLevelPolicyError("Error reading common name: {}".format(strerror(errno)))
            ex.errno = errno
            raise ex

        return name

    def _eq(self, Common other):
        """Low-level equality check (C pointers)."""
        return self.handle == other.handle

    def __contains__(self, other):
        return other in self.perms

    @property
    def perms(self):
        """The set of the common's permissions."""
        cdef qpol_iterator_t *iter
        if qpol_common_get_perm_iter(self.policy.handle, self.handle, &iter):
            raise MemoryError

        return set(qpol_iterator_factory(self.policy, iter, string_factory_iter))

    def statement(self):
        return "common {0}\n{{\n\t{1}\n}}".format(self, '\n\t'.join(self.perms))


cdef class ObjClass(PolicySymbol):

    """An object class."""

    cdef const qpol_class_t *handle

    def __str__(self):
        cdef const char *name

        if qpol_class_get_name(self.policy.handle, self.handle, &name):
            ex = LowLevelPolicyError("Error reading object class name: {}".format(strerror(errno)))
            ex.errno = errno
            raise ex

        return name

    def __contains__(self, other):
        try:
            if other in self.common.perms:
                return True
        except NoCommon:
            pass

        return other in self.perms

    def _eq(self, ObjClass other):
        """Low-level equality check (C pointers)."""
        return self.handle == other.handle

    @property
    def common(self):
        """
        The common that the object class inherits.

        Exceptions:
        NoCommon    The object class does not inherit a common.
        """
        cdef const qpol_common_t *c
        if qpol_class_get_common(self.policy.handle, self.handle, &c):
            ex = LowLevelPolicyError("Error reading common for class: {}".format(strerror(errno)))
            ex.errno = errno
            raise ex

        if c:
            return common_factory(self.policy, c)
        else:
            raise NoCommon("{0} does not inherit a common.".format(self))

    @property
    def constraints(self):
        """The constraints that apply to this class."""
        cdef qpol_iterator_t *iter
        if qpol_class_get_constraint_iter(self.policy.handle, self.handle, &iter):
            ex = LowLevelPolicyError("Error reading class constraints: {}".format(strerror(errno)))
            ex.errno = errno
            raise ex

        return qpol_iterator_factory(self.policy, iter, constraint_factory_iter)

    @property
    def perms(self):
        """The set of the object class's permissions."""

        cdef qpol_iterator_t *iter
        if qpol_class_get_perm_iter(self.policy.handle, self.handle, &iter):
            raise MemoryError

        return set(qpol_iterator_factory(self.policy, iter, string_factory_iter))

    def statement(self):
        stmt = "class {0}\n".format(self)

        try:
            stmt += "inherits {0}\n".format(self.common)
        except NoCommon:
            pass

        # a class that inherits may not have additional permissions
        perms = self.perms
        if len(perms) > 0:
            stmt += "{{\n\t{0}\n}}".format('\n\t'.join(perms))

        return stmt

    @property
    def validatetrans(self):
        """The validatetrans that apply to this class."""
        cdef qpol_iterator_t *iter
        if qpol_class_get_validatetrans_iter(self.policy.handle, self.handle, &iter):
            ex = LowLevelPolicyError("Error reading class validatetranses: {}".format(
                                     strerror(errno)))
            ex.errno = errno
            raise ex

        return qpol_iterator_factory(self.policy, iter, validatetrans_factory_iter)
