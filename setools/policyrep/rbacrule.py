# Copyright 2014, 2016, Tresys Technology, LLC
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

from . import exception
from . import qpol
from . import rule
from . import role
from . import typeattr


def rbac_rule_factory(policy, name):
    """Factory function for creating RBAC rule objects."""

    if isinstance(name, qpol.qpol_role_allow_t):
        return RoleAllow(policy, name)
    elif isinstance(name, qpol.qpol_role_trans_t):
        return RoleTransition(policy, name)
    else:
        raise TypeError("RBAC rules cannot be looked up.")


def expanded_rbac_rule_factory(original, source, target):
    """
    Factory function for creating expanded RBAC rules.

    original    The RBAC rule the expanded rule originates from.
    source      The source type of the expanded rule.
    target      The target type of the expanded rule.
    """

    if isinstance(original, (ExpandedRoleAllow, ExpandedRoleTransition)):
        return original
    elif isinstance(original, RoleAllow):
        rule = ExpandedRoleAllow(original.policy, original.qpol_symbol)
    elif isinstance(original, RoleTransition):
        rule = ExpandedRoleTransition(original.policy, original.qpol_symbol)
    else:
        raise TypeError("The original rule must be an RBAC rule class.")

    rule.source = source
    rule.target = target
    rule.origin = original
    return rule


def validate_ruletype(t):
    """Validate RBAC rule types."""
    if t not in ["allow", "role_transition"]:
        raise exception.InvalidRBACRuleType("{0} is not a valid RBAC rule type.".format(t))

    return t


class RoleAllow(rule.PolicyRule):

    """A role allow rule."""

    def __str__(self):
        return "{0.ruletype} {0.source} {0.target};".format(self)

    def __hash__(self):
        return hash("{0.ruletype}|{0.source}|{0.target}".format(self))

    ruletype = "allow"

    @property
    def source(self):
        """The rule's source role."""
        return role.role_factory(self.policy, self.qpol_symbol.source_role(self.policy))

    @property
    def target(self):
        """The rule's target role."""
        return role.role_factory(self.policy, self.qpol_symbol.target_role(self.policy))

    @property
    def tclass(self):
        """The rule's object class."""
        raise exception.RuleUseError("Role allow rules do not have an object class.")

    @property
    def default(self):
        """The rule's default role."""
        raise exception.RuleUseError("Role allow rules do not have a default role.")

    def expand(self):
        """Expand the rule into an equivalent set of rules without attributes."""
        for s, t in itertools.product(self.source.expand(), self.target.expand()):
            yield expanded_rbac_rule_factory(self, s, t)


class RoleTransition(rule.PolicyRule):

    """A role_transition rule."""

    def __str__(self):
        return "{0.ruletype} {0.source} {0.target}:{0.tclass} {0.default};".format(self)

    ruletype = "role_transition"

    @property
    def source(self):
        """The rule's source role."""
        return role.role_factory(self.policy, self.qpol_symbol.source_role(self.policy))

    @property
    def target(self):
        """The rule's target type/attribute."""
        return typeattr.type_or_attr_factory(self.policy, self.qpol_symbol.target_type(self.policy))

    @property
    def default(self):
        """The rule's default role."""
        return role.role_factory(self.policy, self.qpol_symbol.default_role(self.policy))

    def expand(self):
        """Expand the rule into an equivalent set of rules without attributes."""
        for s, t in itertools.product(self.source.expand(), self.target.expand()):
            yield expanded_rbac_rule_factory(self, s, t)


class ExpandedRoleAllow(RoleAllow):

    """An expanded role allow rule."""

    source = None
    target = None
    origin = None


class ExpandedRoleTransition(RoleTransition):

    """An expanded role_transition rule."""

    source = None
    target = None
    origin = None
