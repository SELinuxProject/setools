# Copyright 2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: GPL-2.0-only
#
# Until this is fixed for cython:
# pylint: disable=undefined-variable,no-member
import unittest
from unittest.mock import Mock, patch

from setools import SELinuxPolicy
from setools.exception import InvalidInitialSid


@unittest.skip("Needs to be reworked for cython")
@patch('setools.policyrep.context.context_factory', lambda x, y: y)
class InitialSIDTest(unittest.TestCase):

    @staticmethod
    def mock_sid(name):
        sid = Mock(qpol.qpol_isid_t)
        sid.name.return_value = name
        sid.context.return_value = name + "_context"
        return sid

    @classmethod
    def setUpClass(cls):
        cls.p = SELinuxPolicy("tests/policyrep/initsid.conf")

    def test_001_factory(self):
        """InitialSID: factory on qpol object."""
        q = self.mock_sid("test1")
        sid = initialsid_factory(self.p.policy, q)
        self.assertEqual("test1", sid.qpol_symbol.name(self.p.policy))

    def test_002_factory_object(self):
        """InitialSID: factory on InitialSID object."""
        q = self.mock_sid("test2")
        sid1 = initialsid_factory(self.p.policy, q)
        sid2 = initialsid_factory(self.p.policy, sid1)
        self.assertIs(sid2, sid1)

    def test_003_factory_lookup(self):
        """InitialSID: factory lookup."""
        sid = initialsid_factory(self.p.policy, "kernel")
        self.assertEqual("kernel", sid.qpol_symbol.name(self.p.policy))

    def test_004_factory_lookup_invalid(self):
        """InitialSID: factory lookup."""
        with self.assertRaises(InvalidInitialSid):
            initialsid_factory(self.p.policy, "INVALID")

    def test_010_string(self):
        """InitialSID: basic string rendering."""
        q = self.mock_sid("test10")
        sid = initialsid_factory(self.p.policy, q)
        self.assertEqual("test10", str(sid))

    def test_020_statement(self):
        """InitialSID: context."""
        q = self.mock_sid("test20")
        sid = initialsid_factory(self.p.policy, q)
        self.assertEqual("test20_context", sid.context)

    def test_030_statement(self):
        """InitialSID: statement."""
        q = self.mock_sid("test30")
        sid = initialsid_factory(self.p.policy, q)
        self.assertEqual("sid test30 test30_context", sid.statement())
