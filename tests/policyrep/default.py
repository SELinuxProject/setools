# Copyright 2016, Tresys Technology, LLC
#
# This file is part of SETools.
#
# SETools is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# SETools is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with SETools.  If not, see <http://www.gnu.org/licenses/>.
#
import unittest

try:
    from unittest.mock import Mock, patch
except ImportError:
    from mock import Mock, patch

from setools.policyrep.default import default_factory, validate_ruletype, validate_default_value, \
                                      validate_default_range
from setools.policyrep.exception import InvalidDefaultType, InvalidDefaultValue, \
                                        InvalidDefaultRange, NoDefaults

from setools.policyrep.qpol import qpol_default_object_t, qpol_policy_t


@patch('setools.policyrep.objclass.class_factory', lambda x, y: y)
class DefaultTest(unittest.TestCase):

    @staticmethod
    def mock_default(objclass=None, user=None, role=None, type_=None, range_=None):
        d = Mock(qpol_default_object_t)
        d.object_class.return_value = objclass
        d.user_default.return_value = user
        d.role_default.return_value = role
        d.type_default.return_value = type_
        d.range_default.return_value = range_
        return d

    def setUp(self):
        self.p = Mock(qpol_policy_t)

    def test_001_factory_user(self):
        """Default: factory on qpol object with user default."""
        q = self.mock_default("test1", "user1")
        defaults = list(default_factory(self.p, q))
        self.assertEqual(1, len(defaults))

        d = defaults[0]
        self.assertEqual("default_user", d.ruletype)
        self.assertEqual("test1", d.tclass)

    def test_002_factory_role(self):
        """Default: factory on qpol object with role default."""
        q = self.mock_default("test2", role="role2")
        defaults = list(default_factory(self.p, q))
        self.assertEqual(1, len(defaults))

        d = defaults[0]
        self.assertEqual("default_role", d.ruletype)
        self.assertEqual("test2", d.tclass)

    def test_003_factory_type(self):
        """Default: factory on qpol object with type default."""
        q = self.mock_default("test3", type_="type3")
        defaults = list(default_factory(self.p, q))
        self.assertEqual(1, len(defaults))

        d = defaults[0]
        self.assertEqual("default_type", d.ruletype)
        self.assertEqual("test3", d.tclass)

    def test_004_factory_range(self):
        """Default: factory on qpol object with range default."""
        q = self.mock_default("test4", range_="range4 low_high")
        defaults = list(default_factory(self.p, q))
        self.assertEqual(1, len(defaults))

        d = defaults[0]
        self.assertEqual("default_range", d.ruletype)
        self.assertEqual("test4", d.tclass)

    def test_005_factory_multiple(self):
        """Default: factory on qpol object with mulitple defaults."""
        q = self.mock_default("test5", "user5", "role5", "type5", "range5a range5b")
        defaults = sorted(default_factory(self.p, q))
        self.assertEqual(4, len(defaults))

        d = defaults[0]
        self.assertEqual("default_range", d.ruletype)
        self.assertEqual("test5", d.tclass)

        d = defaults[1]
        self.assertEqual("default_role", d.ruletype)
        self.assertEqual("test5", d.tclass)

        d = defaults[2]
        self.assertEqual("default_type", d.ruletype)
        self.assertEqual("test5", d.tclass)

        d = defaults[3]
        self.assertEqual("default_user", d.ruletype)
        self.assertEqual("test5", d.tclass)

    def test_010_user(self):
        """Default: default_user methods/attributes."""
        q = self.mock_default("test10", "user10")
        defaults = list(default_factory(self.p, q))
        self.assertEqual(1, len(defaults))

        d = defaults[0]
        self.assertEqual("default_user", d.ruletype)
        self.assertEqual("test10", d.tclass)
        self.assertEqual("user10", d.default)
        self.assertEqual("default_user test10 user10;", str(d))
        self.assertEqual(str(d), d.statement())

    def test_011_role(self):
        """Default: default_role methods/attributes."""
        q = self.mock_default("test11", role="role11")
        defaults = list(default_factory(self.p, q))
        self.assertEqual(1, len(defaults))

        d = defaults[0]
        self.assertEqual("default_role", d.ruletype)
        self.assertEqual("test11", d.tclass)
        self.assertEqual("role11", d.default)
        self.assertEqual("default_role test11 role11;", str(d))
        self.assertEqual(str(d), d.statement())

    def test_012_type(self):
        """Default: default_type methods/attributes."""
        q = self.mock_default("test12", type_="type12")
        defaults = list(default_factory(self.p, q))
        self.assertEqual(1, len(defaults))

        d = defaults[0]
        self.assertEqual("default_type", d.ruletype)
        self.assertEqual("test12", d.tclass)
        self.assertEqual("type12", d.default)
        self.assertEqual("default_type test12 type12;", str(d))
        self.assertEqual(str(d), d.statement())

    def test_013_range(self):
        """Default: default_range methods/attributes."""
        q = self.mock_default("test13", range_="range13a range13b")
        defaults = list(default_factory(self.p, q))
        self.assertEqual(1, len(defaults))

        d = defaults[0]
        self.assertEqual("default_range", d.ruletype)
        self.assertEqual("test13", d.tclass)
        self.assertEqual("range13a", d.default)
        self.assertEqual("range13b", d.default_range)
        self.assertEqual("default_range test13 range13a range13b;", str(d))
        self.assertEqual(str(d), d.statement())

    def test_020_validate_ruletype(self):
        """Default: validate rule type."""
        for r in ["default_user", "default_role", "default_type", "default_range"]:
            self.assertEqual(r, validate_ruletype(r))

    def test_021_validate_ruletype_invalid(self):
        """Default: invalid ruletype"""
        with self.assertRaises(InvalidDefaultType):
            validate_ruletype("INVALID")

    def test_030_validate_default(self):
        """Default: validate default value."""
        for d in ["source", "target"]:
            self.assertEqual(d, validate_default_value(d))

    def test_031_validate_default_invalid(self):
        """Default query: invalid default value"""
        with self.assertRaises(InvalidDefaultValue):
            validate_default_value("INVALID")

    def test_040_validate_default_range(self):
        """Default: validate default range."""
        for r in ["low", "high", "low_high"]:
            self.assertEqual(r, validate_default_range(r))

    def test_041_validate_default_range_invalid(self):
        """Default query: invalid default range"""
        with self.assertRaises(InvalidDefaultRange):
            validate_default_range("INVALID")
