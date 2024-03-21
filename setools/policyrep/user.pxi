# Copyright 2014, Tresys Technology, LLC
# Copyright 2017-2018, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: LGPL-2.1-only
#

cdef object _user_cache = WeakKeyDefaultDict(dict)


cdef class User(PolicySymbol):

    """A user."""

    cdef:
        readonly frozenset roles
        Level _level
        Range _range

    @staticmethod
    cdef inline User factory(SELinuxPolicy policy, sepol.user_datum_t *symbol):
        """Factory function for constructing User objects."""
        cdef User u
        try:
            return _user_cache[policy][<uintptr_t>symbol]
        except KeyError:
            u = User.__new__(User)
            _user_cache[policy][<uintptr_t>symbol] = u
            u.policy = policy
            u.key = <uintptr_t>symbol
            u.name = policy.user_value_to_name(symbol.s.value - 1)

            # object_r is implicitly added to all roles by the compiler.
            # technically it is incorrect to skip it, but policy writers
            # and analysts don't expect to see it in results, and it
            # will confuse, especially for role set equality user queries.
            u.roles = frozenset(r for r in RoleEbitmapIterator.factory(policy, &symbol.roles.roles)
                       if r != "object_r")

            if policy.mls:
                u._level = Level.factory(policy, &symbol.exp_dfltlevel)
                u._range = Range.factory(policy, &symbol.exp_range)

            return u

    @property
    def mls_level(self):
        """The user's default MLS level."""
        if self._level:
            return self._level
        else:
            raise MLSDisabled

    @property
    def mls_range(self):
        """The user's MLS range."""
        if self._range:
            return self._range
        else:
            raise MLSDisabled

    def statement(self):
        cdef:
            list roles = list(str(r) for r in self.roles)
            str stmt = f"user {self.name} roles "
            size_t count = len(roles)

        if count == 1:
            stmt += roles[0]
        else:
            stmt += f"{{ {' '.join(sorted(roles))} }}"

        if self._level:
            stmt += f" level {self.mls_level} range {self.mls_range};"
        else:
            stmt += ";"

        return stmt


#
# Iterator Classes
#
cdef class UserHashtabIterator(HashtabIterator):

    """Iterate over users in the policy."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.hashtab_t *table):
        """Factory function for creating User iterators."""
        i = UserHashtabIterator()
        i.policy = policy
        i.table = table
        i.reset()
        return i

    def __next__(self):
        super().__next__()
        return User.factory(self.policy, <sepol.user_datum_t *>self.curr.datum)


cdef class UserEbitmapIterator(EbitmapIterator):

    """Iterate over a user ebitmap."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.ebitmap_t *bmap):
        """Factory function for creating User ebitmap iterators."""
        i = UserEbitmapIterator()
        i.policy = policy
        i.bmap = bmap
        i.reset()
        return i

    def __next__(self):
        super().__next__()
        return User.factory(self.policy, self.policy.user_value_to_datum(self.bit))
