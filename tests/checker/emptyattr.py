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
import unittest

from ..policyrep.util import compile_policy

from setools.checker.emptyattr import EmptyTypeAttr
from setools.exception import InvalidCheckOption, InvalidCheckValue


class EmptyTypeAttrTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.p = compile_policy("tests/checker/emptyattr.conf")

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.p.path)

    def test_invalid_option(self):
        """Test invalid option"""
        with self.assertRaises(InvalidCheckOption):
            config = {"INVALID": "option"}
            check = EmptyTypeAttr(self.p, "test_invalid_option", config)

    def test_attr_setting(self):
        """EmptyTypeAttr test attr setting."""
        config = {"attr": "test1"}
        check = EmptyTypeAttr(self.p, "test_attr_setting", config)

        expected = self.p.lookup_typeattr("test1")
        self.assertEqual(expected, check.attr)

    def test_attr_setting_fail(self):
        """EmptyTypeAttr test attr setting with invalid attr."""
        with self.assertRaises(InvalidCheckValue):
            config = {"attr": "FAILATTR"}
            check = EmptyTypeAttr(self.p, "test_attr_setting_fail", config)

    def test_attr_setting_missing(self):
        """EmptyTypeAttr test attr setting missing."""
        with self.assertRaises(InvalidCheckValue):
            config = {}
            check = EmptyTypeAttr(self.p, "test_attr_setting_missing", config)

    def test_missingok_setting(self):
        """EmptyTypeAttr test missing_ok setting."""
        config = {"attr": "test1",
                  "missing_ok": "true"}
        check = EmptyTypeAttr(self.p, "test_missingok_setting", config)
        self.assertTrue(check.missing_ok)

        config = {"attr": "test1",
                  "missing_ok": " YeS "}
        check = EmptyTypeAttr(self.p, "test_missingok_setting", config)
        self.assertTrue(check.missing_ok)

        config = {"attr": "test1",
                  "missing_ok": " 1 "}
        check = EmptyTypeAttr(self.p, "test_missingok_setting", config)
        self.assertTrue(check.missing_ok)

        config = {"attr": "test1",
                  "missing_ok": " No "}
        check = EmptyTypeAttr(self.p, "test_missingok_setting", config)
        self.assertFalse(check.missing_ok)

    def test_pass(self):
        """EmptyTypeAttr test pass."""
        with open("/dev/null", "w") as fd:
            config = {"attr": "test1"}
            check = EmptyTypeAttr(self.p, "test_pass", config)
            check.output = fd
            result = check.run()
            self.assertEqual(0, len(result))

    def test_pass_missingok(self):
        """EmptyTypeAttr test pass by missing."""
        with open("/dev/null", "w") as fd:
            config = {"attr": "test2",
                      "missing_ok": "true"}
            check = EmptyTypeAttr(self.p, "test_pass_missingok", config)
            check.output = fd
            result = check.run()
            self.assertEqual(0, len(result))

    def test_fail(self):
        """EmptyTypeAttr test fail."""
        with open("/dev/null", "w") as fd:
            # also verify missing_ok doesn't induce a pass
            # when the attr exists
            config = {"attr": "test3",
                      "missing_ok": "true"}
            check = EmptyTypeAttr(self.p, "test_fail", config)
            check.output = fd
            result = check.run()
            expected = [self.p.lookup_type("test3_hit1"),
                        self.p.lookup_type("test3_hit2")]
            self.assertListEqual(expected, result)
