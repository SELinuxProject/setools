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

#
# Classes
#
class RBACRuletype(PolicyEnum):

    """An enumeration of RBAC rule types."""

    allow = 1
    role_transition = 2


cdef class RoleAllow(PolicyRule):

    """A role allow rule."""

    cdef:
        sepol.role_allow_t *handle
        readonly object ruletype

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.role_allow_t *symbol):
        """Factory function for creating RoleAllow objects."""
        r = RoleAllow()
        r.policy = policy
        r.handle = symbol
        return r

    def __cinit__(self):
        self.ruletype = RBACRuletype.allow

    def __str__(self):
        return "{0.ruletype} {0.source} {0.target};".format(self)

    def _eq(self, RoleAllow other):
        """Low-level equality check (C pointers)."""
        return self.handle == other.handle

    @property
    def source(self):
        """The rule's source role."""
        return Role.factory(self.policy,
                            self.policy.role_value_to_datum(self.handle.role - 1))

    @property
    def target(self):
        """The rule's target role."""
        return Role.factory(self.policy,
                            self.policy.role_value_to_datum(self.handle.new_role - 1))

    @property
    def tclass(self):
        """The rule's object class."""
        raise RuleUseError("Role allow rules do not have an object class.")

    @property
    def default(self):
        """The rule's default role."""
        raise RuleUseError("Role allow rules do not have a default role.")

    def expand(self):
        """Expand the rule into an equivalent set of rules without attributes."""
        for s, t in itertools.product(self.source.expand(), self.target.expand()):
            """Factory function for creating ExpandedRoleAllow objects."""
            r = ExpandedRoleAllow()
            r.policy = self.policy
            r.handle = self.handle
            r.source = s
            r.target = t
            r.origin = self
            yield r


cdef class RoleTransition(PolicyRule):

    """A role_transition rule."""

    cdef:
        sepol.role_trans_t *handle
        readonly object ruletype

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.role_trans_t *symbol):
        """Factory function for creating RoleTransition objects."""
        r = RoleTransition()
        r.policy = policy
        r.handle = symbol
        return r

    def __cinit__(self):
        self.ruletype = RBACRuletype.role_transition

    def __str__(self):
        return "{0.ruletype} {0.source} {0.target}:{0.tclass} {0.default};".format(self)

    def _eq(self, RoleTransition other):
        """Low-level equality check (C pointers)."""
        return self.handle == other.handle

    @property
    def source(self):
        """The rule's source role."""
        return Role.factory(self.policy,
                            self.policy.role_value_to_datum(self.handle.role - 1))

    @property
    def target(self):
        """The rule's target type/attribute."""
        return type_or_attr_factory(self.policy,
                                    self.policy.type_value_to_datum(self.handle.type - 1))

    @property
    def tclass(self):
        """The rule's object class."""
        return ObjClass.factory(self.policy,
                                self.policy.class_value_to_datum(self.handle.tclass - 1))

    @property
    def default(self):
        """The rule's default role."""
        return Role.factory(self.policy,
                            self.policy.role_value_to_datum(self.handle.new_role - 1))

    def expand(self):
        """Expand the rule into an equivalent set of rules without attributes."""
        for s, t in itertools.product(self.source.expand(), self.target.expand()):
            r = ExpandedRoleTransition()
            r.policy = self.policy
            r.handle = self.handle
            r.source = s
            r.target = t
            r.origin = self
            yield r


cdef class ExpandedRoleAllow(RoleAllow):

    """An expanded role allow rule."""

    cdef:
        public object source
        public object target
        public object origin

    def __hash__(self):
        return hash("{0.ruletype}|{0.source}|{0.target}".format(self))

    def __lt__(self, other):
        return str(self) < str(other)


cdef class ExpandedRoleTransition(RoleTransition):

    """An expanded role_transition rule."""

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
cdef class RoleAllowIterator(PolicyIterator):

    """Role allow rule iterator."""

    cdef:
        sepol.role_allow_t *head
        sepol.role_allow_t *curr

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.role_allow_t *head):
        """Role allow rule iterator factory."""
        i = RoleAllowIterator()
        i.policy = policy
        i.head = head
        i.reset()
        return i

    def __next__(self):
        if self.curr == NULL:
            raise StopIteration

        item = RoleAllow.factory(self.policy, self.curr)
        self.curr = self.curr.next
        return item

    def __len__(self):
        cdef:
            sepol.role_allow_t *curr
            size_t count = 0

        curr = self.head
        while curr != NULL:
             count += 1
             curr = curr.next

        return count

    def reset(self):
        """Reset the iterator back to the start."""
        self.curr = self.head


cdef class RoleTransitionIterator(PolicyIterator):

    """Role transition rule iterator."""

    cdef:
        sepol.role_trans_t *head
        sepol.role_trans_t *curr

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.role_trans_t *head):
        """Role transition rule iterator factory."""
        i = RoleTransitionIterator()
        i.policy = policy
        i.head = head
        i.reset()
        return i

    def __next__(self):
        if self.curr == NULL:
            raise StopIteration

        item = RoleTransition.factory(self.policy, self.curr)
        self.curr = self.curr.next
        return item

    def __len__(self):
        cdef:
            sepol.role_trans_t *curr
            size_t count = 0

        curr = self.head
        while curr != NULL:
             count += 1
             curr = curr.next

        return count

    def reset(self):
        """Reset the iterator back to the start."""
        self.curr = self.head
