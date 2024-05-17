# Copyright 2014, Tresys Technology, LLC
# Copyright 2017-2018, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: LGPL-2.1-only
#


cdef class Role(PolicySymbol):

    """A role."""

    cdef frozenset _types

    @staticmethod
    cdef inline Role factory(SELinuxPolicy policy, sepol.role_datum_t *symbol):
        """Factory function for creating Role objects."""
        cdef Role r = Role.__new__(Role)
        r.policy = policy
        r.key = <uintptr_t>symbol
        r.name = policy.role_value_to_name(symbol.s.value - 1)
        r._types = frozenset(TypeEbitmapIterator.factory_from_set(policy, &symbol.types))
        return r

    @property
    def dominated_roles(self):
        """The roles that this role dominates."""
        # TODO: do dominated roles even work?
        #return set(RoleEbitmapIterator.factory(self.policy, &self.handle.dominates))
        return frozenset()

    def types(self):
        """Generator which yields the role's set of types."""
        return iter(self._types)

    def statement(self):
        cdef size_t count
        if self.policy.gen_cil:
            stmt = ""
            for t in self._types:
                stmt += f"(roletype {self} {t})\n"
            return stmt
        else:
            types = list(str(t) for t in self._types)
            count = len(types)
            stmt = f"role {self.name}"
            if count == 0:
                return f"role {self.name};"
            if count == 1:
                return f"role {self.name} types {types[0]};"

            return f"role {self.name} types {{ {' '.join(sorted(types))} }};"


#
# Iterator Classes
#
cdef class RoleHashtabIterator(HashtabIterator):

    """Iterate over roles in the policy."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.hashtab_t *table):
        """Factory function for creating Role iterators."""
        i = RoleHashtabIterator()
        i.policy = policy
        i.table = table
        i.reset()
        return i

    def __next__(self):
        super().__next__()
        return Role.factory(self.policy, <sepol.role_datum_t *>self.curr.datum)


cdef class RoleEbitmapIterator(EbitmapIterator):

    """Iterate over a role ebitmap."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.ebitmap_t *bmap):
        """Factory function for creating Role ebitmap iterators."""
        i = RoleEbitmapIterator()
        i.policy = policy
        i.bmap = bmap
        i.reset()
        return i

    def __next__(self):
        super().__next__()
        return Role.factory(self.policy, self.policy.role_value_to_datum(self.bit))
