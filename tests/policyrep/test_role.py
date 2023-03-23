# Copyright 2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: GPL-2.0-only
#
# Until this is fixed for cython:
# pylint: disable=undefined-variable,no-member
import unittest
from unittest.mock import Mock

from setools import SELinuxPolicy
from setools.exception import InvalidRole


@unittest.skip("Needs to be reworked for cython")
class RoleTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.p = SELinuxPolicy("tests/policyrep/role.conf")

    def mock_role_factory(self, name, types):
        """Factory function for Role objects, using a mock qpol object."""
        mock_role = Mock(qpol.qpol_role_t)
        mock_role.name.return_value = name
        mock_role.type_iter = lambda x: iter(types)

        return role_factory(self.p.policy, mock_role)

    def test_001_lookup(self):
        """Role factory policy lookup."""
        role = role_factory(self.p.policy, "role20_r")
        self.assertEqual("role20_r", role.qpol_symbol.name(self.p.policy))

    def test_002_lookup_invalid(self):
        """Role factory policy invalid lookup."""
        with self.assertRaises(InvalidRole):
            role_factory(self.p.policy, "INVALID")

    def test_003_lookup_object(self):
        """Role factory policy lookup of Role object."""
        role1 = role_factory(self.p.policy, "role20_r")
        role2 = role_factory(self.p.policy, role1)
        self.assertIs(role2, role1)

    def test_010_string(self):
        """Role basic string rendering."""
        role = self.mock_role_factory("rolename10", ['type1'])
        self.assertEqual("rolename10", str(role))

    def test_020_statement_type(self):
        """Role statement, one type."""
        role = self.mock_role_factory("rolename20", ['type30'])
        self.assertEqual("role rolename20 types type30;", role.statement())

    def test_021_statement_two_types(self):
        """Role statement, two types."""
        role = self.mock_role_factory("rolename21", ['type31a', 'type31b'])
        self.assertEqual("role rolename21 types { type31a type31b };", role.statement())

    def test_022_statement_decl(self):
        """Role statement, no types."""
        # This is an unlikely corner case, where a role
        # has been declared but has no types.
        role = self.mock_role_factory("rolename22", [])
        self.assertEqual("role rolename22;", role.statement())

    def test_030_types(self):
        """Role types generator."""
        role = self.mock_role_factory("rolename", ['type31b', 'type31c'])
        self.assertEqual(['type31b', 'type31c'], sorted(role.types()))

    def test_040_expand(self):
        """Role expansion"""
        role = self.mock_role_factory("rolename", ['type31a', 'type31b', 'type31c'])
        expanded = list(role.expand())
        self.assertEqual(1, len(expanded))
        self.assertIs(role, expanded[0])
