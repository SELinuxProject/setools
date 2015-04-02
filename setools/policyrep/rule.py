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
from . import exception
from . import symbol
from . import objclass


class PolicyRule(symbol.PolicySymbol):

    """This is base class for policy rules."""

    def __str__(self):
        raise NotImplementedError

    @property
    def ruletype(self):
        """The rule type for the rule."""
        return self.qpol_symbol.rule_type(self.policy)

    @property
    def source(self):
        """
        The source for the rule. This should be overridden by
        subclasses.
        """
        raise NotImplementedError

    @property
    def target(self):
        """
        The target for the rule. This should be overridden by
        subclasses.
        """
        raise NotImplementedError

    @property
    def tclass(self):
        """The object class for the rule."""
        return objclass.class_factory(self.policy, self.qpol_symbol.object_class(self.policy))

    @property
    def default(self):
        """
        The default for the rule. This should be overridden by
        subclasses.
        """
        raise NotImplementedError

    @property
    def conditional(self):
        """The conditional expression for this rule."""
        # Most rules cannot be conditional.
        raise exception.RuleNotConditional

    def statement(self):
        return str(self)
