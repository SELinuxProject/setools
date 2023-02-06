"""Unit test mixin classes."""
# Copyright 2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: GPL-2.0-only
#
# pylint: disable=too-few-public-methods
import unittest

from setools.exception import RuleNotConditional, RuleUseError


class ValidateRule(unittest.TestCase):

    """Mixin for validating policy rules."""

    def validate_rule(self, rule, ruletype, source, target, tclass, last_item, cond=None,
                      cond_block=None, xperm=None):
        """Validate a rule."""
        self.assertEqual(ruletype, rule.ruletype)
        self.assertEqual(source, rule.source)
        self.assertEqual(target, rule.target)
        self.assertEqual(tclass, rule.tclass)

        try:
            # This is the common case.
            self.assertSetEqual(last_item, rule.perms)
        except (AttributeError, RuleUseError):
            self.assertEqual(last_item, rule.default)

        if cond:
            self.assertEqual(cond, rule.conditional)
        else:
            self.assertRaises(RuleNotConditional, getattr, rule, "conditional")

        if cond_block is not None:
            self.assertEqual(cond_block, rule.conditional_block)

        if xperm:
            self.assertEqual(xperm, rule.xperm_type)
            self.assertTrue(rule.extended)
        else:
            self.assertRaises(AttributeError, getattr, rule, "xperm_type")
            self.assertFalse(rule.extended)
