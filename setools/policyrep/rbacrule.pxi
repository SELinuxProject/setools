# Copyright 2014, 2016, Tresys Technology, LLC
# Copyright 2016-2017, Chris PeBenito <pebenito@ieee.org>
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
# Role allow factory functions
#
cdef inline RoleAllow role_allow_factory_iter(SELinuxPolicy policy, QpolIteratorItem symbol):
    """Factory function variant for iterating over RoleAllow objects."""
    return role_allow_factory(policy, <const qpol_role_allow_t *> symbol.obj)


cdef inline RoleAllow role_allow_factory(SELinuxPolicy policy, const qpol_role_allow_t *symbol):
    """Factory function for creating RoleAllow objects."""
    r = RoleAllow()
    r.policy = policy
    r.handle = symbol
    return r


#
# Role transition factory functions
#
cdef inline RoleTransition role_trans_factory_iter(SELinuxPolicy policy, QpolIteratorItem symbol):
    """Factory function variant for iterating over RoleTransition objects."""
    return role_trans_factory(policy, <const qpol_role_trans_t *> symbol.obj)


cdef inline RoleTransition role_trans_factory(SELinuxPolicy policy, const qpol_role_trans_t *symbol):
    """Factory function for creating RoleTransition objects."""
    r = RoleTransition()
    r.policy = policy
    r.handle = symbol
    return r

#
# Expanded RBAC rule factory functions
#
cdef inline ExpandedRoleAllow expanded_role_allow_factory(RoleAllow original, source, target):
    """Factory function for creating ExpandedRoleAllow objects."""
    r = ExpandedRoleAllow()
    r.policy = original.policy
    r.handle = original.handle
    r.source = source
    r.target = target
    r.origin = original
    return r


cdef inline ExpandedRoleTransition expanded_role_trans_factory(RoleTransition original, source, target):
    """Factory function for creating ExpandedRoleTransition objects."""
    r = ExpandedRoleTransition()
    r.policy = original.policy
    r.handle = original.handle
    r.source = source
    r.target = target
    r.origin = original
    return r


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
        const qpol_role_allow_t *handle
        readonly object ruletype

    def __init__(self):
        self.ruletype = RBACRuletype.allow

    def __str__(self):
        return "{0.ruletype} {0.source} {0.target};".format(self)

    def _eq(self, RoleAllow other):
        """Low-level equality check (C pointers)."""
        return self.handle == other.handle

    @property
    def source(self):
        """The rule's source role."""
        cdef const qpol_role_t *r
        if qpol_role_allow_get_source_role(self.policy.handle, self.handle, &r):
            ex = LowLevelPolicyError("Error reading source role for role allow rule: {}".format(
                                     strerror(errno)))
            ex.errno = errno
            raise ex

        return role_factory(self.policy, r)

    @property
    def target(self):
        """The rule's target role."""
        cdef const qpol_role_t *r
        if qpol_role_allow_get_target_role(self.policy.handle, self.handle, &r):
            ex = LowLevelPolicyError("Error reading target role for role allow rule: {}".format(
                                     strerror(errno)))
            ex.errno = errno
            raise ex

        return role_factory(self.policy, r)

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
            yield expanded_role_allow_factory(self, s, t)


cdef class RoleTransition(PolicyRule):

    """A role_transition rule."""

    cdef:
        const qpol_role_trans_t *handle
        readonly object ruletype

    def __init__(self):
        self.ruletype = RBACRuletype.role_transition

    def __str__(self):
        return "{0.ruletype} {0.source} {0.target}:{0.tclass} {0.default};".format(self)

    def _eq(self, RoleTransition other):
        """Low-level equality check (C pointers)."""
        return self.handle == other.handle

    @property
    def source(self):
        """The rule's source role."""
        cdef const qpol_role_t *r
        if qpol_role_trans_get_source_role(self.policy.handle, self.handle, &r):
            ex = LowLevelPolicyError("Error reading source role for role_transition rule: {}".
                                     format(strerror(errno)))
            ex.errno = errno
            raise ex

        return role_factory(self.policy, r)

    @property
    def target(self):
        """The rule's target type/attribute."""
        cdef const qpol_type_t *t
        if qpol_role_trans_get_target_type(self.policy.handle, self.handle, &t):
            ex = LowLevelPolicyError("Error reading target type/attr for role_transition rule: {}".
                                     format(strerror(errno)))
            ex.errno = errno
            raise ex

        return type_or_attr_factory(self.policy, t)

    @property
    def tclass(self):
        """The rule's object class."""
        cdef const qpol_class_t *c
        if qpol_role_trans_get_object_class(self.policy.handle, self.handle, &c):
            ex = LowLevelPolicyError("Error reading class for role_transition rule: {}".format(
                                     strerror(errno)))
            ex.errno = errno
            raise ex

        return class_factory(self.policy, c)

    @property
    def default(self):
        """The rule's default role."""
        cdef const qpol_role_t *r
        if qpol_role_trans_get_default_role(self.policy.handle, self.handle, &r):
            ex = LowLevelPolicyError("Error reading default role for role_transition rule: {}".
                                     format(strerror(errno)))
            ex.errno = errno
            raise ex

        return role_factory(self.policy, r)

    def expand(self):
        """Expand the rule into an equivalent set of rules without attributes."""
        for s, t in itertools.product(self.source.expand(), self.target.expand()):
            yield expanded_role_trans_factory(self, s, t)


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
