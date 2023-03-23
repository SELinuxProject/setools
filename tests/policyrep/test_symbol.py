# Copyright 2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: GPL-2.0-only
#
# Until this is fixed for cython:
# pylint: disable=undefined-variable
import copy
import unittest
from unittest.mock import Mock, patch

from setools import SELinuxPolicy


@unittest.skip("Needs to be reworked for cython")
class PolicySymbolTest(unittest.TestCase):

    """Tests for base symbol class methods."""

    def mock_symbol_factory(self, name):
        """Factory function for Role objects, using a mock qpol object."""
        mock_role = Mock(qpol.qpol_role_t)
        mock_role.name.return_value = name
        mock_role.this = name

        mock_policy = Mock(qpol.qpol_policy_t)
        return PolicySymbol(mock_policy, mock_role)

    def test_001_string(self):
        """Symbol: string representation"""
        sym = self.mock_symbol_factory("test1")
        self.assertEqual("test1", str(sym))

    def test_010_hash(self):
        """Symbol: hash"""
        sym = self.mock_symbol_factory("test10")
        self.assertEqual(hash("test10"), hash(sym))

    def test_020_eq(self):
        """Symbol: equality"""
        sym1 = self.mock_symbol_factory("test20")
        sym2 = self.mock_symbol_factory("test20")
        self.assertEqual(sym1, sym2)

    def test_021_eq(self):
        """Symbol: equality with string"""
        sym = self.mock_symbol_factory("test21")
        self.assertEqual("test21", sym)

    def test_030_ne(self):
        """Symbol: inequality"""
        sym1 = self.mock_symbol_factory("test30a")
        sym2 = self.mock_symbol_factory("test30b")
        self.assertNotEqual(sym1, sym2)

    def test_031_ne(self):
        """Symbol: inequality with string"""
        sym = self.mock_symbol_factory("test31a")
        self.assertNotEqual("test31b", sym)

    def test_040_lt(self):
        """Symbol: less-than"""
        sym1 = self.mock_symbol_factory("test40a")
        sym2 = self.mock_symbol_factory("test40b")
        self.assertTrue(sym1 < sym2)

        sym1 = self.mock_symbol_factory("test40")
        sym2 = self.mock_symbol_factory("test40")
        self.assertFalse(sym1 < sym2)

        sym1 = self.mock_symbol_factory("test40b")
        sym2 = self.mock_symbol_factory("test40a")
        self.assertFalse(sym1 < sym2)

    def test_050_deepcopy(self):
        """Symbol: deep copy"""
        sym1 = self.mock_symbol_factory("test50")
        sym2 = copy.deepcopy(sym1)
        self.assertIs(sym1.policy, sym2.policy)
        self.assertIs(sym1.qpol_symbol, sym2.qpol_symbol)
