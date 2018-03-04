# Copyright 2014-2015, Tresys Technology, LLC
# Copyright 2016-2018, Chris PeBenito <pebenito@ieee.org>
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

cdef class Context(PolicySymbol):

    """A SELinux security context/security attribute."""

    cdef sepol.context_struct_t *handle

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.context_struct_t *symbol):
        """Factory function for creating Context objects."""
        r = Context()
        r.policy = policy
        r.handle = symbol
        return r

    def __str__(self):
        try:
            return "{0.user}:{0.role}:{0.type_}:{0.range_}".format(self)
        except MLSDisabled:
            return "{0.user}:{0.role}:{0.type_}".format(self)

    def _eq(self, Context other):
        """Low-level equality check (C pointers)."""
        return self.handle == other.handle

    @property
    def user(self):
        """The user portion of the context."""
        return User.factory(self.policy, self.policy.user_value_to_datum(self.handle.user - 1))

    @property
    def role(self):
        """The role portion of the context."""
        return Role.factory(self.policy, self.policy.role_value_to_datum(self.handle.role - 1))

    @property
    def type_(self):
        """The type portion of the context."""
        return Type.factory(self.policy, self.policy.type_value_to_datum(self.handle.type - 1))

    @property
    def range_(self):
        """The MLS range of the context."""
        if not self.policy.mls:
            raise MLSDisabled

        return Range.factory(self.policy, &self.handle.range)

    def statement(self):
        raise NoStatement
