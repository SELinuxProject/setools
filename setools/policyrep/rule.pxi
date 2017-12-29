# Copyright 2014, 2016, Tresys Technology, LLC
# Copyright 2017, Chris PeBenito <pebenito@ieee.org>
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

cdef class PolicyRule(PolicySymbol):

    """This is base class for policy rules."""

    cdef readonly bint extended

    def __init__(self):
        self.extended = False

    def __str__(self):
        raise NotImplementedError

    def __lt__(self, other):
        return str(self) < str(other)

    @property
    def ruletype(self):
        """The rule type for the rule."""
        raise NotImplementedError

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
        raise NotImplementedError

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
        raise RuleNotConditional

    @property
    def conditional_block(self):
        """The conditional block of the rule (T/F)"""
        # Most rules cannot be conditional.
        raise RuleNotConditional

    def expand(self):
        """Expand the rule into an equivalent set of rules without attributes."""
        raise NotImplementedError

    def statement(self):
        return str(self)
