# Copyright 2014-2015, Tresys Technology, LLC
# Copyright 2016-2018, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: LGPL-2.1-only
#

cdef class Context(PolicyObject):

    """A SELinux security context/security attribute."""

    cdef:
        readonly User user
        readonly Role role
        readonly Type type_
        Range _range

    @staticmethod
    cdef inline Context factory(SELinuxPolicy policy, sepol.context_struct_t *symbol):
        """Factory function for creating Context objects."""
        cdef Context c = Context.__new__(Context)
        c.policy = policy
        c.key = <uintptr_t>symbol
        c.user = User.factory(policy, policy.user_value_to_datum(symbol.user - 1))
        c.role = Role.factory(policy, policy.role_value_to_datum(symbol.role - 1))
        c.type_ = Type.factory(policy, policy.type_value_to_datum(symbol.type - 1))

        if policy.mls:
            c._range = Range.factory(policy, &symbol.range)

        return c

    def __str__(self):
        if self._range:
            return "{0.user}:{0.role}:{0.type_}:{0.range_}".format(self)
        else:
            return "{0.user}:{0.role}:{0.type_}".format(self)

    @property
    def range_(self):
        """The MLS range of the context."""
        if self._range:
            return self._range
        else:
            raise MLSDisabled

    def statement(self):
        raise NoStatement
