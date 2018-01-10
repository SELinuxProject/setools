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

#
# Factory functions
#
cdef inline InitialSID initialsid_factory_lookup(SELinuxPolicy policy, str name):
    """Factory function variant for constructing InitialSID objects by name."""

    cdef const qpol_isid_t *symbol
    if qpol_policy_get_isid_by_name(policy.handle, name.encode(), &symbol):
        raise InvalidInitialSid("{0} is not a valid initial SID".format(name))

    return initialsid_factory(policy, symbol)


cdef inline InitialSID initialsid_factory_iter(SELinuxPolicy policy, QpolIteratorItem symbol):
    """Factory function variant for iterating over InitialSID objects."""
    return initialsid_factory(policy, <const qpol_isid_t *> symbol.obj)


cdef inline InitialSID initialsid_factory(SELinuxPolicy policy, const qpol_isid_t *symbol):
    """Factory function for creating InitialSID objects."""
    r = InitialSID()
    r.policy = policy
    r.handle = symbol
    return r


#
# Class
#
cdef class InitialSID(PolicySymbol):

    """An initial SID statement."""

    cdef const qpol_isid_t *handle

    def __str__(self):
        cdef const char *name

        if qpol_isid_get_name(self.policy.handle, self.handle, &name):
            ex = LowLevelPolicyError("Error reading initial SID name: {}".format(strerror(errno)))
            ex.errno = errno
            raise ex

        return intern(name)

    def _eq(self, InitialSID other):
        """Low-level equality check (C pointers)."""
        return self.handle == other.handle

    @property
    def context(self):
        """The context for this initial SID."""
        cdef const qpol_context_t *ctx
        if qpol_isid_get_context(self.policy.handle, self.handle, &ctx):
            ex = LowLevelPolicyError("Error reading initial sid context: {}".format(
                                     strerror(errno)))
            ex.errno = errno
            raise ex

        return context_factory(self.policy, ctx)

    def statement(self):
        return "sid {0} {0.context}".format(self)
