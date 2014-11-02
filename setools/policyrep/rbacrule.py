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
from . import objclass


class RBACRule(rule.PolicyRule):

    """An RBAC rule."""

    def __str__(self):
        try:
            return "role_transition {0.source} {0.target}:{0.tclass} {0.default};".format(self)
        except rule.InvalidRuleUse:
            return "allow {0.source} {0.target};".format(self)

    @property
    def source(self):
        """The rule's source role."""
        return role.Role(self.policy, self.qpol_symbol.source_role(self.policy))

    @property
    def target(self):
        """
        The rule's target role (role allow) or target type/attribute
        (role_transition).
        """
        try:
            return role.Role(self.policy, self.qpol_symbol.target_role(self.policy))
        except AttributeError:
            return typeattr.TypeAttr(self.policy, self.qpol_symbol.target_type(self.policy))

    @property
    def tclass(self):
        """The rule's object class."""
        try:
            return objclass.ObjClass(self.policy, self.qpol_symbol.object_class(self.policy))
        except AttributeError:
            raise rule.InvalidRuleUse(
                "Role allow rules do not have an object class.")

    @property
    def default(self):
        """The rule's default role."""
        try:
            return role.Role(self.policy, self.qpol_symbol.default_role(self.policy))
        except AttributeError:
            raise rule.InvalidRuleUse(
                "Role allow rules do not have a default role.")
