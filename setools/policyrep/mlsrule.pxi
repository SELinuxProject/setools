# Copyright 2014, 2016, Tresys Technology, LLC
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
import itertools


class MLSRuletype(PolicyEnum):

    """An enumeration of MLS rule types."""

    range_transition = 1


cdef class MLSRule(PolicyRule):

    """An MLS rule."""

    cdef:
        sepol.range_trans_t *handle
        object rng
        readonly object ruletype

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.range_trans_t *symbol, sepol.mls_range_t *rng):
        """Factory function for creating MLSRule objects."""
        r = MLSRule(Range.factory(policy, rng))
        r.policy = policy
        r.handle = symbol
        return r

    def __cinit__(self, rng):
        self.ruletype = MLSRuletype.range_transition
        self.rng = rng

    def __str__(self):
        return "{0.ruletype} {0.source} {0.target}:{0.tclass} {0.default};".format(self)

    def _eq(self, MLSRule other):
        """Low-level equality check (C pointers)."""
        return self.handle == other.handle

    @property
    def source(self):
        """The rule's source type/attribute."""
        return type_or_attr_factory(self.policy,
                                    self.policy.type_value_to_datum(self.handle.source_type - 1))

    @property
    def target(self):
        """The rule's target type/attribute."""
        return type_or_attr_factory(self.policy,
                                    self.policy.type_value_to_datum(self.handle.target_type - 1))

    @property
    def tclass(self):
        """The rule's object class."""
        return ObjClass.factory(self.policy,
                                self.policy.class_value_to_datum(self.handle.target_class - 1))

    @property
    def default(self):
        """The rule's default range."""
        return self.rng

    def expand(self):
        """Expand the rule into an equivalent set of rules without attributes."""
        for s, t in itertools.product(self.source.expand(), self.target.expand()):
            r = ExpandedMLSRule(self.rng)
            r.policy = self.policy
            r.handle = self.handle
            r.source = s
            r.target = t
            r.origin = self
            yield r


cdef class ExpandedMLSRule(MLSRule):

    """An expanded MLS rule."""

    cdef:
        public object source
        public object target
        public object origin

    def __hash__(self):
        try:
            cond = self.conditional
            cond_block = self.conditional_block
        except RuleNotConditional:
            cond = None
            cond_block = None

        return hash("{0.ruletype}|{0.source}|{0.target}|{0.tclass}|{1}|{2}".format(
            self, cond, cond_block))

    def __lt__(self, other):
        return str(self) < str(other)


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
