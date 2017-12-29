# Copyright 2014, 2016 Tresys Technology, LLC
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
cdef DefaultIterator default_iterator_factory(SELinuxPolicy policy, qpol_iterator_t *iter):
    """Factory function for default_* statement iterator."""
    i = DefaultIterator()
    i.policy = policy
    i.iter = iter
    return i


cdef inline Default default_factory(SELinuxPolicy policy, ObjClass tclass,
                                    const qpol_default_object_t *handle, user, role, type_, range_):

    """Factory function for creating default_* statement objects."""

    if user:
        obj = Default()
        obj.policy = policy
        obj.handle = handle
        obj.ruletype = DefaultRuletype.default_user
        obj.tclass = tclass
        obj._default = DefaultValue[user]
        return obj

    if role:
        obj = Default()
        obj.policy = policy
        obj.handle = handle
        obj.ruletype = DefaultRuletype.default_role
        obj.tclass = tclass
        obj._default = DefaultValue[role]
        return obj

    if type_:
        obj = Default()
        obj.policy = policy
        obj.handle = handle
        obj.ruletype = DefaultRuletype.default_type
        obj.tclass = tclass
        obj._default = DefaultValue[type_]
        return obj

    if range_:
        # range_ is something like "source low_high"
        rng = range_.split()
        obj = RangeDefault()
        obj.policy = policy
        obj.handle = handle
        obj.ruletype = DefaultRuletype.default_range
        obj.tclass = tclass
        obj._default = DefaultValue[rng[0]]
        obj.default_range = DefaultRangeValue[rng[1]]
        return obj

    raise ValueError("At least one of user, role, type_, or range_ must be specified.")


#
# Classes
#
class DefaultRuletype(PolicyEnum):

    """Enumeration of default rule types."""
    default_user = 1
    default_role = 2
    default_type = 3
    default_range = 4


class DefaultValue(PolicyEnum):

    """Enumeration of default values."""
    source = 1
    target = 2


class DefaultRangeValue(PolicyEnum):

    """Enumeration of default range values."""
    low = 1
    high = 2
    low_high = 3


cdef class Default(PolicySymbol):

    """Base class for default_* statements."""

    cdef:
        const qpol_default_object_t *handle
        public object ruletype
        public object tclass
        object _default

    # the default object is not exposed as a Python
    # attribute, as it collides with CPython code

    def _eq(self, Default other):
        """Low-level equality check (C pointers)."""
        return self.handle == other.handle \
                and self.ruletype == other.ruletype

    def __str__(self):
        return "{0.ruletype} {0.tclass} {0.default};".format(self)

    def __hash__(self):
        return hash("{0.ruletype}|{0.tclass}".format(self))

    def __lt__(self, other):
        # this is used by Python sorting functions
        return str(self) < str(other)

    @property
    def default(self):
        return self._default

    def statement(self):
        return str(self)


cdef class RangeDefault(Default):

    """A default_range statement."""

    cdef public object default_range

    def __str__(self):
        return "{0.ruletype} {0.tclass} {0.default} {0.default_range};".format(self)


cdef class DefaultIterator:

    """
    Iterate over all policy defaults.

    The low level policy groups default_* settings by object class.
    Since each class can have up to four default_* statements,
    this has a sub iterator which yields up to
    four Default objects.
    """

    cdef:
        qpol_iterator_t *iter
        SELinuxPolicy policy
        object sub_iter

    def __dealloc__(self):
        if self.iter:
            qpol_iterator_destroy(&self.iter)

    def __iter__(self):
        return self

    def __next__(self):
        cdef void *item
        cdef const qpol_default_object_t *symbol
        cdef const qpol_class_t *cls
        cdef const char *user
        cdef const char *role
        cdef const char *type_
        cdef const char *range_

        # drain sub-iterator first, if one exists
        if self.sub_iter:
            try:
                return self.sub_iter.__next__()
            except StopIteration:
                # sub_iter completed, clear
                self.sub_iter = None

        while not qpol_iterator_end(self.iter):
            qpol_iterator_get_item(self.iter, &item)
            qpol_iterator_next(self.iter)
            symbol = <const qpol_default_object_t *>item

            # qpol will essentially iterate over all classes
            # and emit NULL for classes that don't set a default.
            if qpol_default_object_get_class(self.policy.handle, symbol, &cls):
                ex = LowLevelPolicyError("Error reading default's class: {}".format(
                                         strerror(errno)))
                ex.errno = errno
                raise ex

            if cls:
                tclass = class_factory(self.policy, cls)
            else:
                continue

            dfts = []
            if qpol_default_object_get_user_default(self.policy.handle, symbol, &user):
                ex = LowLevelPolicyError("Error reading default's user: {}".format(
                                         strerror(errno)))
                ex.errno = errno
                raise ex
            elif user:
                dfts.append(default_factory(self.policy, tclass, symbol, user, None, None, None))

            if qpol_default_object_get_role_default(self.policy.handle, symbol, &role):
                ex = LowLevelPolicyError("Error reading default's role: {}".format(
                                         strerror(errno)))
                ex.errno = errno
                raise ex
            elif role:
                dfts.append(default_factory(self.policy, tclass, symbol, None, role, None, None))

            if qpol_default_object_get_type_default(self.policy.handle, symbol, &type_):
                ex = LowLevelPolicyError("Error reading default's type: {}".format(
                                         strerror(errno)))
                ex.errno = errno
                raise ex
            elif type_:
                dfts.append(default_factory(self.policy, tclass, symbol, None, None, type_, None))

            if qpol_default_object_get_range_default(self.policy.handle, symbol, &range_):
                ex = LowLevelPolicyError("Error reading default's range: {}".format(
                                         strerror(errno)))
                ex.errno = errno
                raise ex
            elif range_:
                dfts.append(default_factory(self.policy, tclass, symbol, None, None, None, range_))

            if not dfts:
                raise LowLevelPolicyError("Policy structure error: {} did not have any defaults.".
                                          format(strerror(errno)))

            self.sub_iter = iter(dfts)
            return self.sub_iter.__next__()

        raise StopIteration
