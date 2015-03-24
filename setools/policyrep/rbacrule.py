# Copyright 2014, Tresys Technology, LLC
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
from . import qpol
from . import rule
from . import role
from . import typeattr


class InvalidRBACRuleType(rule.InvalidRuleType):

    """Exception for invalid RBAC rule types."""
    pass


def rbac_rule_factory(policy, symbol):
    """Factory function for creating RBAC rule objects."""

    if isinstance(symbol, qpol.qpol_role_allow_t):
        return RoleAllow(policy, symbol)
    elif isinstance(symbol, qpol.qpol_role_trans_t):
        return RoleTransition(policy, symbol)
    else:
        raise TypeError("RBAC rules cannot be looked up.")


def validate_ruletype(types):
    """Validate RBAC rule types."""
    for t in types:
        if t not in ["allow", "role_transition"]:
            raise InvalidTERuleType("{0} is not a valid RBAC rule type.".format(t))


class RoleAllow(rule.PolicyRule):

    """A role allow rule."""

    def __str__(self):
        return "allow {0.source} {0.target};".format(self)

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
        raise rule.RuleUseError("Role allow rules do not have an object class.")

    @property
    def default(self):
        """The rule's default role."""
        raise rule.RuleUseError("Role allow rules do not have a default role.")


class RoleTransition(rule.PolicyRule):

    """A role_transition rule."""

    def __str__(self):
        return "role_transition {0.source} {0.target}:{0.tclass} {0.default};".format(self)

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
