# Copyright 2020, Microsoft Corporation
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

import os
import logging
import unittest

from ..policyrep.util import compile_policy

from setools.checker import util
from setools.exception import InvalidCheckValue


class CheckerUtilTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.p = compile_policy("tests/checker/util.conf")
        cls.log = logging.getLogger("this_is_a_log_test")

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.p.path)

    def test_config_list_to_class(self):
        """Test config_list_to_class() success."""
        expected = set((self.p.lookup_class("infoflow"),
                        self.p.lookup_class("infoflow2")))

        result = util.config_list_to_class(self.p, " infoflow , infoflow2 ")
        self.assertIsInstance(result, frozenset)
        self.assertSetEqual(expected, result)

    def test_config_list_to_class_unset(self):
        """Test config_list_to_class() with empty input."""
        result = util.config_list_to_class(self.p, "")
        self.assertIsInstance(result, frozenset)
        self.assertEqual(0, len(result))

        result = util.config_list_to_class(self.p, None)
        self.assertIsInstance(result, frozenset)
        self.assertEqual(0, len(result))

    def test_config_list_to_class_error(self):
        """Test config_list_to_class() with invalid class."""
        with self.assertRaises(InvalidCheckValue):
            util.config_list_to_class(self.p, "FAIL")

        with self.assertRaises(InvalidCheckValue):
            util.config_list_to_class(self.p, "infoflow, FAIL")

    def test_config_list_to_perms_no_class(self):
        """Test config_list_to_perms() success with no classes set."""
        expected = set(("hi_w", "null"))

        result = util.config_list_to_perms(self.p, " hi_w , null ", tclass=None)
        self.assertIsInstance(result, frozenset)
        self.assertSetEqual(expected, result)

    def test_config_list_to_perms_no_class_unset(self):
        """Test config_list_to_perms() with empty input with no classes set."""
        result = util.config_list_to_perms(self.p, "", tclass=None)
        self.assertIsInstance(result, frozenset)
        self.assertEqual(0, len(result))

        result = util.config_list_to_perms(self.p, None, tclass=None)
        self.assertIsInstance(result, frozenset)
        self.assertEqual(0, len(result))

    def test_config_list_to_perms_no_class_fail(self):
        """Test config_list_to_perms() failure with no classes set."""
        with self.assertRaises(InvalidCheckValue):
            util.config_list_to_perms(self.p, " hi_w , null , invalid_perm ", tclass=None)

    def test_config_list_to_perms_class(self):
        """Test config_list_to_perms() success with classes set."""
        classes = set((self.p.lookup_class("infoflow2"),
                       self.p.lookup_class("infoflow3")))
        expected = set(("super_r", "null"))

        result = util.config_list_to_perms(self.p, " super_r , null ", tclass=classes)
        self.assertIsInstance(result, frozenset)
        self.assertSetEqual(expected, result)

    def test_config_list_to_perms_class_unset(self):
        """Test config_list_to_perms() with empty input with classes set."""
        classes = set((self.p.lookup_class("infoflow2"),
                       self.p.lookup_class("infoflow3")))

        result = util.config_list_to_perms(self.p, "", tclass=classes)
        self.assertIsInstance(result, frozenset)
        self.assertEqual(0, len(result))

        result = util.config_list_to_perms(self.p, None, tclass=classes)
        self.assertIsInstance(result, frozenset)
        self.assertEqual(0, len(result))

    def test_config_list_to_perms_class_fail(self):
        """Test config_list_to_perms() failure with classes set."""
        classes = set((self.p.lookup_class("infoflow2"),
                       self.p.lookup_class("infoflow3")))

        with self.assertRaises(InvalidCheckValue):
            # super_none isn't in either class
            util.config_list_to_perms(self.p, " super_none , null ", tclass=classes)

    def test_config_to_type_or_attr(self):
        """Test config_to_type_or_attr() success."""
        expected = self.p.lookup_type("test1")
        result = util.config_to_type_or_attr(self.p, " test1 ")
        self.assertEqual(expected, result)

        expected = self.p.lookup_typeattr("test10c")
        result = util.config_to_type_or_attr(self.p, " test10c ")
        self.assertEqual(expected, result)

    def test_config_to_type_or_attr_empty(self):
        """Test config_to_type_or_attr() success."""
        result = util.config_to_type_or_attr(self.p, "")
        self.assertIsNone(result)

        result = util.config_to_type_or_attr(self.p, None)
        self.assertIsNone(result)

    def test_config_to_type_or_attr_fail(self):
        """Test config_to_type_or_attr() failure."""
        with self.assertRaises(InvalidCheckValue):
            util.config_to_type_or_attr(self.p, "FAIL")

    def test_config_list_to_types_or_attrs(self):
        """Test config_list_to_types_or_attrs() success."""
        expected = set((self.p.lookup_type("test1"),
                        self.p.lookup_typeattr("test10c")))

        result = util.config_list_to_types_or_attrs(self.log, self.p, " test1, test10c ")
        self.assertIsInstance(result, frozenset)
        self.assertSetEqual(expected, result)

    def test_config_list_to_types_or_attrs_expand(self):
        """Test config_list_to_types_or_attrs() success and expanded attributes."""
        expected = set((self.p.lookup_type("test1"),
                        self.p.lookup_type("test10t3"),
                        self.p.lookup_type("test10t4"),
                        self.p.lookup_type("test10t5"),
                        self.p.lookup_type("test10t7")))

        result = util.config_list_to_types_or_attrs(self.log, self.p, " test1, test10c ",
                                                    expand=True)
        self.assertIsInstance(result, frozenset)
        self.assertSetEqual(expected, result)

    def test_config_list_to_types_or_attrs_unset(self):
        """Test config_list_to_types_or_attrs() with empty input."""
        result = util.config_list_to_types_or_attrs(self.log, self.p, "")
        self.assertIsInstance(result, frozenset)
        self.assertEqual(0, len(result))

        result = util.config_list_to_types_or_attrs(self.log, self.p, None)
        self.assertIsInstance(result, frozenset)
        self.assertEqual(0, len(result))

    def test_config_list_to_types_or_attrs_fail_strict(self):
        """Test config_list_to_types_or_attrs() with strict failure."""
        with self.assertRaises(InvalidCheckValue):
            util.config_list_to_types_or_attrs(self.log, self.p, "FAIL", strict=True)

    def test_config_list_to_types_or_attrs_fail_not_strict(self):
        """Test config_list_to_types_or_attrs() with not strict failure."""

        with self.assertLogs(logger=self.log, level=logging.INFO):
            result = util.config_list_to_types_or_attrs(self.log, self.p, "FAIL", strict=False)

        self.assertIsInstance(result, frozenset)
        self.assertEqual(0, len(result))
