# Copyright 2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: GPL-2.0-only
#
# Until this is fixed for cython:
# pylint: disable=undefined-variable
import unittest
from unittest.mock import Mock


@unittest.skip("Needs to be reworked for cython")
class PolCapTest(unittest.TestCase):

    @staticmethod
    def mock_cap(name):
        cap = Mock(qpol.qpol_polcap_t)
        cap.name.return_value = name
        return cap

    def setUp(self):
        self.p = Mock(qpol.qpol_policy_t)

    def test_001_factory(self):
        """PolCap: factory on qpol object."""
        q = self.mock_cap("test1")
        cap = polcap_factory(self.p, q)
        self.assertEqual("test1", cap.qpol_symbol.name(self.p))

    def test_002_factory_object(self):
        """PolCap: factory on PolCap object."""
        q = self.mock_cap("test2")
        cap1 = polcap_factory(self.p, q)
        cap2 = polcap_factory(self.p, cap1)
        self.assertIs(cap2, cap1)

    def test_003_factory_lookup(self):
        """PolCap: factory lookup."""
        with self.assertRaises(TypeError):
            polcap_factory(self.p, "open_perms")

    def test_010_string(self):
        """PolCap: basic string rendering."""
        q = self.mock_cap("test10")
        cap = polcap_factory(self.p, q)
        self.assertEqual("test10", str(cap))

    def test_020_statement(self):
        """PolCap: statement."""
        q = self.mock_cap("test20")
        cap = polcap_factory(self.p, q)
        self.assertEqual("policycap test20;", cap.statement())
