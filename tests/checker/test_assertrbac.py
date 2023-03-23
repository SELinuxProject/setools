# Copyright 2020, Microsoft Corporation
# Copyright 2020, Chris PeBenito <pebenito@ieee.org>
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

from setools import RBACRuletype
from setools.checker.assertrbac import AssertRBAC
from setools.exception import InvalidCheckValue, InvalidCheckOption


class AssertRBACTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.p = compile_policy("tests/checker/assertrbac.conf")

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.p.path)

    def test_unconfigured(self):
        """Test unconfigured."""
        with self.assertRaises(InvalidCheckValue):
            config = {}
            check = AssertRBAC(self.p, "test_unconfigured", config)

    def test_invalid_option(self):
        """Test invalid option"""
        with self.assertRaises(InvalidCheckOption):
            config = {"INVALID": "option"}
            check = AssertRBAC(self.p, "test_invalid_option", config)

    def test_source(self):
        """Test source setting."""

        with self.subTest("Success"):
            config = {"source": "src"}
            check = AssertRBAC(self.p, "test_source", config)

            expected = self.p.lookup_role("src")
            self.assertEqual(expected, check.source)

        with self.subTest("Failure"):
            with self.assertRaises(InvalidCheckValue):
                config = {"source": "FAIL"}
                check = AssertRBAC(self.p, "test_source_fail", config)

    def test_target(self):
        """Test target setting."""

        with self.subTest("Success"):
            config = {"target": "tgt"}
            check = AssertRBAC(self.p, "test_target", config)

            expected = self.p.lookup_role("tgt")
            self.assertEqual(expected, check.target)

        with self.subTest("Failure"):
            with self.assertRaises(InvalidCheckValue):
                config = {"target": "FAIL2"}
                check = AssertRBAC(self.p, "test_target_fail", config)

    def test_exempt_source(self):
        """Test exempt_source setting."""
        with self.subTest("Success"):
            config = {"source": "system",
                      "exempt_source": " exempt_src1   exempt_src2 "}
            check = AssertRBAC(self.p, "test_exempt_source", config)

            # exempt_src2 is an attr
            expected = set((self.p.lookup_role("exempt_src1"),
                            self.p.lookup_role("exempt_src2")))
            self.assertIsInstance(check.exempt_source, frozenset)
            self.assertSetEqual(expected, check.exempt_source)

        with self.subTest("Success, missing role ignored"):
            """Test exempt_source missing role is ignroed."""
            config = {"source": "system",
                      "exempt_source": "FAIL  exempt_src2"}
            check = AssertRBAC(self.p, "test_source_missing_ignored", config)

            # exempt_src2 is an attr
            expected = set((self.p.lookup_role("exempt_src2"),))
            self.assertIsInstance(check.exempt_source, frozenset)
            self.assertSetEqual(expected, check.exempt_source)

    def test_exempt_target(self):
        """Test exempt_target setting."""
        with self.subTest("Success"):
            config = {"target": "system",
                      "exempt_target": " exempt_tgt1   exempt_tgt2 "}
            check = AssertRBAC(self.p, "test_exempt_target", config)

            # exempt_tgt2 is an attr
            expected = set((self.p.lookup_role("exempt_tgt1"),
                            self.p.lookup_role("exempt_tgt2")))
            self.assertIsInstance(check.exempt_target, frozenset)
            self.assertSetEqual(expected, check.exempt_target)

        with self.subTest("Success, missing role ignored"):
            config = {"target": "system",
                      "exempt_target": "FAIL  exempt_tgt2"}
            check = AssertRBAC(self.p, "test_target_missing_ignored", config)

            # exempt_tgt2 is an attr
            expected = set((self.p.lookup_role("exempt_tgt2"),))
            self.assertIsInstance(check.exempt_target, frozenset)
            self.assertSetEqual(expected, check.exempt_target)

    def test_expect_source(self):
        """Test expect_source setting."""
        with self.subTest("Success"):
            config = {"target": "tgt",
                      "expect_source": " exempt_src1   exempt_src2 "}
            check = AssertRBAC(self.p, "test_expect_source", config)

            # exempt_src2 is an attr
            expected = set((self.p.lookup_role("exempt_src1"),
                            self.p.lookup_role("exempt_src2")))
            self.assertIsInstance(check.expect_source, frozenset)
            self.assertSetEqual(expected, check.expect_source)

        with self.subTest("Failure"):
            with self.assertRaises(InvalidCheckValue):
                config = {"target": "tgt",
                          "expect_source": " source1   INVALID "}
                check = AssertRBAC(self.p, "test_expect_source_fail", config)

    def test_expect_target(self):
        """Test expect_target setting."""
        with self.subTest("Success"):
            config = {"source": "src",
                      "expect_target": " exempt_tgt1   exempt_tgt2 "}
            check = AssertRBAC(self.p, "test_expect_target", config)

            # exempt_tgt2 is an attr
            expected = set((self.p.lookup_role("exempt_tgt1"),
                            self.p.lookup_role("exempt_tgt2")))
            self.assertIsInstance(check.expect_target, frozenset)
            self.assertSetEqual(expected, check.expect_target)

        with self.subTest("Failure"):
            with self.assertRaises(InvalidCheckValue):
                config = {"source": "src",
                          "expect_target": " target1   INVALID "}
                check = AssertRBAC(self.p, "test_expect_target_fail", config)

    def test_check_passes(self):
        """Test the check passes, no matches"""
        config = {"source": "src",
                  "target": "tgt"}
        check = AssertRBAC(self.p, "test_check_passes", config)
        self.assertFalse(check.run())

    def test_check_passes_exempt_source_role(self):
        """Test the check passes, exempt_source_role"""
        config = {"target": "target1",
                  "exempt_source": "source1"}
        check = AssertRBAC(self.p, "test_check_passes_exempt_source_role", config)
        self.assertFalse(check.run())

    def test_check_passes_exempt_target_role(self):
        """Test the check passes, exempt_target_role"""
        config = {"target": "target2",
                  "exempt_source": "source2"}
        check = AssertRBAC(self.p, "test_check_passes_exempt_target_role", config)
        self.assertFalse(check.run())

    def test_check_passes_expect_source(self):
        """Test the check passes, expect_source"""
        config = {"target": "target3",
                  "expect_source": "source3a source3b"}
        check = AssertRBAC(self.p, "test_check_passes_expect_source", config)
        self.assertFalse(check.run())

    def test_check_passes_expect_target(self):
        """Test the check passes, expect_target"""
        config = {"source": "source4",
                  "expect_target": "target4a target4b"}
        check = AssertRBAC(self.p, "test_check_passes_expect_target", config)
        self.assertFalse(check.run())

    def test_check_passes_expect_exempt_source(self):
        """"Test the check passes with both expected and exempted sources."""
        config = {"target": "target5",
                  "expect_source": "source5a",
                  "exempt_source": "source5b"}
        check = AssertRBAC(self.p, "test_check_passes_expect_exempt_source", config)
        self.assertFalse(check.run())

    def test_check_passes_expect_exempt_target(self):
        """"Test the check passes with both expected and exempted targets."""
        config = {"source": "source6",
                  "expect_target": "target6a",
                  "exempt_target": "target6b"}
        check = AssertRBAC(self.p, "test_check_passes_expect_exempt_target", config)
        self.assertFalse(check.run())

    def test_check_fails(self):
        """Test the check fails"""
        with open("/dev/null", "w") as fd:
            config = {"source": "source7",
                      "expect_target": "target7a",
                      "exempt_target": "target7b"}
            check = AssertRBAC(self.p, "test_check_passes_exempt_target_attr", config)
            check.output = fd
            result = check.run()
            self.assertEqual(1, len(result), msg=result)
            rule = result[0]
            self.assertEqual(RBACRuletype.allow, rule.ruletype)
            self.assertEqual("source7", rule.source)
            self.assertEqual("target7c", rule.target)

    def test_check_fails_expect_source(self):
        """Test the check fails, expect_source"""
        config = {"target": "target8",
                  "expect_source": "source8"}
        check = AssertRBAC(self.p, "test_check_fails_expect_source", config)
        result = check.run()
        self.assertEqual(1, len(result), msg=result)
        self.assertIn("source8", result[0])

    def test_check_fails_expect_target(self):
        """Test the check fails, expect_target"""
        config = {"source": "source9",
                  "expect_target": "target9"}
        check = AssertRBAC(self.p, "test_check_fails_expect_target", config)
        result = check.run()
        self.assertEqual(1, len(result), msg=result)
        self.assertIn("target9", result[0])
