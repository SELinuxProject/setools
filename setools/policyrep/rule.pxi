# Copyright 2014, 2016, Tresys Technology, LLC
# Copyright 2017-2018, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: LGPL-2.1-only
#

cdef class PolicyRule(PolicyObject):

    """This is base class for policy rules."""

    cdef:
        readonly object ruletype
        readonly object source
        readonly object target
        readonly object origin
        # This is initialized to False:
        readonly bint extended

    @property
    def conditional(self):
        """The conditional expression for this rule."""
        # Most rule types cannot be conditional.
        raise RuleNotConditional

    @property
    def conditional_block(self):
        """The conditional block of the rule (T/F)"""
        # Most rule types cannot be conditional.
        raise RuleNotConditional

    @property
    def default(self):
        """The rule's default."""
        raise RuleUseError

    @property
    def filename(self):
        """The filename for this rule."""
        # Most rule types do not have filenames.
        raise RuleUseError

    @property
    def perms(self):
        """The permissions for this rule."""
        raise RuleUseError

    @property
    def tclass(self):
        """The rule's object class."""
        raise RuleUseError

    @property
    def xperm_type(self):
        """The extended permission type for this rule."""
        # Most rule types are not extended.
        raise RuleUseError

    def enabled(self, **kwargs):
        """
        Determine if the rule is enabled, given the stated boolean values.

        Keyword Parameters: bool_name=True|False
        Each keyword parameter name corresponds to a Boolean name
        in the expression and the state to use in the evaluation.
        If a Boolean value is not set, its default value is used.
        Extra values are ignored.

        Return:     bool
        """
        # Most rule types cannot be conditional, thus are always enabled.
        return True

    def expand(self):
        """Expand the rule into an equivalent set of rules without attributes."""
        raise NotImplementedError
