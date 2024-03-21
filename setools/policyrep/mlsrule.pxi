# Copyright 2014, 2016, Tresys Technology, LLC
# Copyright 2016-2018, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: LGPL-2.1-only
#


class MLSRuletype(PolicyEnum):

    """An enumeration of MLS rule types."""

    range_transition = 1


cdef class MLSRule(PolicyRule):

    """An MLS rule."""

    cdef:
        readonly ObjClass tclass
        object rng

    @staticmethod
    cdef inline MLSRule factory(SELinuxPolicy policy, sepol.range_trans_t *symbol,
                                sepol.mls_range_t *rng):
        """Factory function for creating MLSRule objects."""
        cdef MLSRule r = MLSRule.__new__(MLSRule)
        r.policy = policy
        r.key = <uintptr_t>symbol
        r.ruletype = MLSRuletype.range_transition
        r.source = type_or_attr_factory(policy, policy.type_value_to_datum(symbol.source_type - 1))
        r.target = type_or_attr_factory(policy, policy.type_value_to_datum(symbol.target_type - 1))
        r.tclass = ObjClass.factory(policy, policy.class_value_to_datum(symbol.target_class - 1))
        r.rng = Range.factory(policy, rng)
        r.origin = None
        return r

    def __hash__(self):
        return hash(f"{self.ruletype}|{self.source}|{self.target}|{self.tclass}|None|None")

    def __lt__(self, other):
        return str(self) < str(other)

    @property
    def default(self):
        """The rule's default range."""
        return self.rng

    def expand(self):
        """Expand the rule into an equivalent set of rules without attributes."""
        cdef MLSRule r
        if self.origin is None:
            for s, t in itertools.product(self.source.expand(), self.target.expand()):
                r = MLSRule.__new__(MLSRule)
                r.policy = self.policy
                r.key = self.key
                r.ruletype = self.ruletype
                r.source = s
                r.target = t
                r.tclass = self.tclass
                r.rng = self.rng
                r.origin = self
                yield r

        else:
            # this rule is already expanded.
            yield self

    def statement(self):
        return f"{self.ruletype} {self.source} {self.target}:{self.tclass} {self.default};"


#
# Iterators
#
cdef class MLSRuleIterator(HashtabIterator):

    """Iterate over MLS rules in the policy."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.hashtab_t *table):
        """Factory function for creating MLS rule iterators."""
        i = MLSRuleIterator()
        i.policy = policy
        i.table = table
        i.reset()
        return i

    def __next__(self):
        super().__next__()
        return MLSRule.factory(self.policy, <sepol.range_trans_t *>self.curr.key,
                               <sepol.mls_range_t *>self.curr.datum)
