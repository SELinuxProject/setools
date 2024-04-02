# Copyright 2014-2015, Tresys Technology, LLC
# Copyright 2017-2018, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: LGPL-2.1-only
#


cdef class PolicyCapability(PolicySymbol):

    """A policy capability."""

    @staticmethod
    cdef inline PolicyCapability factory(SELinuxPolicy policy, size_t bit):
        """Factory function for creating PolicyCapability objects."""
        cdef PolicyCapability r = PolicyCapability.__new__(PolicyCapability)
        r.policy = policy
        r.name = intern(sepol.sepol_polcap_getname(bit))
        return r

    def __eq__(self, other):
        try:
            return self.policy == other.policy \
                and self.name == other.name
        except AttributeError:
            return self.name == str(other)

    def __hash__(self):
        return hash(self.name)

    def statement(self):
        return f"policycap {self.name};"


cdef class PolicyCapabilityIterator(EbitmapIterator):

    """Iterator for policy capability statements in the policy."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.ebitmap_t *bmap):
        """Factory function for creating PolicyCapability iterators."""
        i = PolicyCapabilityIterator()
        i.policy = policy
        i.bmap = bmap
        i.reset()
        return i

    def __next__(self):
        super().__next__()
        return PolicyCapability.factory(self.policy, self.bit)
