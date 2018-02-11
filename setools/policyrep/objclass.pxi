# Copyright 2014-2015, Tresys Technology, LLC
# Copyright 2017-2018, Chris PeBenito <pebenito@ieee.org>
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

cdef dict _objclass_cache = {}


#
# Classes
#
cdef class Common(PolicySymbol):

    """A common permission set."""

    cdef sepol.common_datum_t *handle

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.common_datum_t *symbol):
        """Factory function for creating Common objects."""
        r = Common()
        r.policy = policy
        r.handle = symbol
        return r

    def __str__(self):
        return intern(self.policy.handle.p.p.sym_val_to_name[sepol.SYM_COMMONS][self.handle.s.value - 1])

    def _eq(self, Common other):
        """Low-level equality check (C pointers)."""
        return self.handle == other.handle

    def __contains__(self, other):
        return other in self.perms

    @property
    def perms(self):
        """The set of the common's permissions."""
        return set(PermissionIterator.factory(self.policy, &self.handle.permissions.table))

    def statement(self):
        return "common {0}\n{{\n\t{1}\n}}".format(self, '\n\t'.join(self.perms))


cdef class ObjClass(PolicySymbol):

    """An object class."""

    cdef sepol.class_datum_t *handle

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.class_datum_t *symbol):
        """Factory function for creating ObjClass objects."""
        try:
            return _objclass_cache[<uintptr_t>symbol]
        except KeyError:
            c = ObjClass()
            c.policy = policy
            c.handle = symbol
            _objclass_cache[<uintptr_t>symbol] = c
            return c

    def __str__(self):
        return intern(self.policy.handle.p.p.sym_val_to_name[sepol.SYM_CLASSES][self.handle.s.value - 1])

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
        if self.handle.comdatum:
            return Common.factory(self.policy, self.handle.comdatum)
        else:
            raise NoCommon("{0} does not inherit a common.".format(self))

    @property
    def constraints(self):
        """The constraints that apply to this class."""
        cdef qpol_iterator_t *iter
        if qpol_class_get_constraint_iter(self.policy.handle, <const qpol_class_t *>self.handle, &iter):
            ex = LowLevelPolicyError("Error reading class constraints: {}".format(strerror(errno)))
            ex.errno = errno
            raise ex

        return qpol_iterator_factory(self.policy, iter, constraint_factory_iter)

    def defaults(self):
        """Iterator for the defaults for this object class."""
        if self.handle.default_user:
            yield Default.factory(self.policy, self, self.handle.default_user, None, None, None)

        if self.handle.default_role:
            yield Default.factory(self.policy, self, None, self.handle.default_role, None, None)

        if self.handle.default_type:
            yield Default.factory(self.policy, self, None, None, self.handle.default_type, None)

        if self.handle.default_range:
            yield Default.factory(self.policy, self, None, None, None, self.handle.default_range)

    @property
    def perms(self):
        """The set of the object class's permissions."""
        return set(PermissionIterator.factory(self.policy, &self.handle.permissions.table))

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
        if qpol_class_get_validatetrans_iter(self.policy.handle, <const qpol_class_t *>self.handle, &iter):
            ex = LowLevelPolicyError("Error reading class validatetranses: {}".format(
                                     strerror(errno)))
            ex.errno = errno
            raise ex

        return qpol_iterator_factory(self.policy, iter, validatetrans_factory_iter)


#
# Iterators
#
cdef class CommonHashtabIterator(HashtabIterator):

    """Iterate over commons in the policy."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.hashtab_t *table):
        """Factory function for creating Role iterators."""
        i = CommonHashtabIterator()
        i.policy = policy
        i.table = table
        i.reset()
        return i

    def __next__(self):
        super().__next__()
        return Common.factory(self.policy, <sepol.common_datum_t *>self.curr.datum)


cdef class ObjClassHashtabIterator(HashtabIterator):

    """Iterate over roles in the policy."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.hashtab_t *table):
        """Factory function for creating Role iterators."""
        i = ObjClassHashtabIterator()
        i.policy = policy
        i.table = table
        i.reset()
        return i

    def __next__(self):
        super().__next__()
        return ObjClass.factory(self.policy, <sepol.class_datum_t *>self.curr.datum)


cdef class PermissionIterator(HashtabIterator):

    """Iterate over permissions."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.hashtab_t *table):
        """Factory function for creating Permission iterators."""
        i = PermissionIterator()
        i.policy = policy
        i.table = table
        i.reset()
        return i

    def __next__(self):
        super().__next__()
        return intern(self.curr.key)
