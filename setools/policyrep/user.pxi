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

cdef inline User user_factory_lookup(SELinuxPolicy policy, str name):
    """Factory function variant for constructing User objects by name."""
    cdef const qpol_user_t *symbol
    if qpol_policy_get_user_by_name(policy.handle, name.encode(), &symbol):
        raise InvalidUser("{0} is not a valid user".format(name))

    return user_factory(policy, symbol)


cdef inline User user_factory_iter(SELinuxPolicy policy, QpolIteratorItem symbol):
    """Factory function variant for iterating over User objects."""
    return user_factory(policy, <const qpol_user_t *> symbol.obj)


cdef inline User user_factory(SELinuxPolicy policy, const qpol_user_t * symbol):
    """Factory function for constructing User objects."""
    u = User()
    u.policy = policy
    u.handle = symbol
    return u


cdef class User(PolicySymbol):
    cdef const qpol_user_t *handle

    def __str__(self):
        cdef const char *name

        if qpol_user_get_name(self.policy.handle, self.handle, &name):
            raise ValueError("Error reading user name")

        return name

    def _eq(self, User other):
        """Low-level equality check (C pointers)."""
        return self.handle == other.handle

    @property
    def roles(self):
        cdef qpol_iterator_t *iter

        if qpol_user_get_role_iter(self.policy.handle, self.handle, &iter):
            raise MemoryError

        roleset = set()

        for role in qpol_iterator_factory(self.policy, iter, role_factory_iter):
            # object_r is implicitly added to all roles by the compiler.
            # technically it is incorrect to skip it, but policy writers
            # and analysts don't expect to see it in results, and it
            # will confuse, especially for role set equality user queries.
            if role != "object_r":
                roleset.add(role)

        return roleset

    @property
    def mls_level(self):
        """The user's default MLS level."""
        cdef const qpol_mls_level_t *l
        if qpol_user_get_dfltlevel(self.policy.handle, self.handle, &l):
            ex = LowLevelPolicyError("Error reading user default level: {}".format(strerror(errno)))
            ex.errno = errno
            raise ex

        return level_factory(self.policy, l)

    @property
    def mls_range(self):
        """The user's MLS range."""
        cdef const qpol_mls_range_t *r
        if qpol_user_get_range(self.policy.handle, self.handle, &r):
            ex = LowLevelPolicyError("Error reading user range: {}".format(strerror(errno)))
            ex.errno = errno
            raise ex

        return range_factory(self.policy, r)

    def statement(self):
        roles = list(str(r) for r in self.roles)
        stmt = "user {0} roles ".format(self)
        if len(roles) > 1:
            stmt += "{{ {0} }}".format(' '.join(roles))
        else:
            stmt += roles[0]

        try:
            stmt += " level {0.mls_level} range {0.mls_range};".format(self)
        except MLSDisabled:
            stmt += ";"

        return stmt
