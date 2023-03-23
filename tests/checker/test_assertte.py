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
import logging
import unittest

from .. import mixins
from ..policyrep.util import compile_policy

from setools import TERuletype
from setools.checker.assertte import AssertTE
from setools.exception import InvalidCheckValue, InvalidCheckOption


class AssertTETest(mixins.ValidateRule, unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.p = compile_policy("tests/checker/assertte.conf")

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.p.path)

    def test_unconfigured(self):
        """Test unconfigured."""
        with self.assertRaises(InvalidCheckValue):
            config = {}
            check = AssertTE(self.p, "test_unconfigured", config)

    def test_invalid_option(self):
        """Test invalid option"""
        with self.assertRaises(InvalidCheckOption):
            config = {"INVALID": "option"}
            check = AssertTE(self.p, "test_invalid_option", config)

    def test_source(self):
        """Test source setting."""
        config = {"source": "src"}
        check = AssertTE(self.p, "test_source", config)

        expected = self.p.lookup_type("src")
        self.assertEqual(expected, check.source)

    def test_source_fail(self):
        """Test source setting failure."""
        with self.assertRaises(InvalidCheckValue):
            config = {"source": "FAIL"}
            check = AssertTE(self.p, "test_source_fail", config)

    def test_target(self):
        """Test target setting."""
        config = {"target": "tgt"}
        check = AssertTE(self.p, "test_target", config)

        expected = self.p.lookup_type("tgt")
        self.assertEqual(expected, check.target)

    def test_target_fail(self):
        """Test target setting failure."""
        with self.assertRaises(InvalidCheckValue):
            config = {"target": "FAIL2"}
            check = AssertTE(self.p, "test_target_fail", config)

    def test_exempt_source(self):
        """Test exempt_source setting."""
        config = {"source": "system",
                  "exempt_source": " exempt_src1   exempt_src2 "}
        check = AssertTE(self.p, "test_exempt_source", config)

        # exempt_src2 is an attr
        expected = set((self.p.lookup_type("exempt_src1"),
                        self.p.lookup_type("exempt_source_type")))
        self.assertIsInstance(check.exempt_source, frozenset)
        self.assertSetEqual(expected, check.exempt_source)

    def test_source_missing_ignored(self):
        """Test exempt_source missing type is ignroed."""
        config = {"source": "system",
                  "exempt_source": "FAIL  exempt_src2"}
        check = AssertTE(self.p, "test_source_missing_ignored", config)

        # exempt_src2 is an attr
        expected = set((self.p.lookup_type("exempt_source_type"),))
        self.assertIsInstance(check.exempt_source, frozenset)
        self.assertSetEqual(expected, check.exempt_source)

    def test_exempt_target(self):
        """Test exempt_target setting."""
        config = {"target": "system",
                  "exempt_target": " exempt_tgt1   exempt_tgt2 "}
        check = AssertTE(self.p, "test_exempt_target", config)

        # exempt_tgt2 is an attr
        expected = set((self.p.lookup_type("exempt_tgt1"),
                        self.p.lookup_type("exempt_target_type")))
        self.assertIsInstance(check.exempt_target, frozenset)
        self.assertSetEqual(expected, check.exempt_target)

    def test_target_missing_ignored(self):
        """Test exempt_target missing type is ignroed."""
        config = {"target": "system",
                  "exempt_target": "FAIL  exempt_tgt2"}
        check = AssertTE(self.p, "test_target_missing_ignored", config)

        # exempt_tgt2 is an attr
        expected = set((self.p.lookup_type("exempt_target_type"),))
        self.assertIsInstance(check.exempt_target, frozenset)
        self.assertSetEqual(expected, check.exempt_target)

    def test_expect_source(self):
        """Test expect_source setting."""
        with self.subTest("Success"):
            config = {"tclass": "infoflow3",
                      "expect_source": " exempt_src1   exempt_src2 "}
            check = AssertTE(self.p, "test_expect_source", config)

            # exempt_src2 is an attr
            expected = set((self.p.lookup_type("exempt_src1"),
                            self.p.lookup_type("exempt_source_type")))
            self.assertIsInstance(check.expect_source, frozenset)
            self.assertSetEqual(expected, check.expect_source)

        with self.subTest("Failure"):
            with self.assertRaises(InvalidCheckValue):
                config = {"tclass": "infoflow3",
                          "expect_source": " source1   INVALID "}
                check = AssertTE(self.p, "test_expect_source_fail", config)

    def test_expect_target(self):
        """Test expect_target setting."""
        with self.subTest("Success"):
            config = {"tclass": "infoflow3",
                      "expect_target": " exempt_tgt1   exempt_tgt2 "}
            check = AssertTE(self.p, "test_expect_target", config)

            # exempt_tgt2 is an attr
            expected = set((self.p.lookup_type("exempt_tgt1"),
                            self.p.lookup_type("exempt_target_type")))
            self.assertIsInstance(check.expect_target, frozenset)
            self.assertSetEqual(expected, check.expect_target)

        with self.subTest("Failure"):
            with self.assertRaises(InvalidCheckValue):
                config = {"tclass": "infoflow3",
                          "expect_target": " target1   INVALID "}
                check = AssertTE(self.p, "test_expect_target_fail", config)

    def test_tclass(self):
        """Test tclass setting."""
        config = {"tclass": "infoflow3  infoflow2"}
        check = AssertTE(self.p, "test_tclass", config)

        expected = set((self.p.lookup_class("infoflow3"),
                        self.p.lookup_class("infoflow2")))
        self.assertEqual(expected, check.tclass)

    def test_tclass_fail(self):
        """Test tclass setting failure."""
        with self.assertRaises(InvalidCheckValue):
            config = {"tclass": "FAIL_class"}
            check = AssertTE(self.p, "test_tclass_fail", config)

    def test_perms(self):
        """Test perms setting."""
        config = {"perms": " hi_w  super_r "}
        check = AssertTE(self.p, "test_perms", config)

        expected = set(("hi_w", "super_r"))
        self.assertEqual(expected, check.perms)

    def test_perms_fail(self):
        """Test perms setting failure."""
        with self.assertRaises(InvalidCheckValue):
            config = {"perms": "FAIL_perms"}
            check = AssertTE(self.p, "test_perms_fail", config)

    def test_check_passes(self):
        """Test the check passes, no matches"""
        config = {"perms": "null"}
        check = AssertTE(self.p, "test_check_passes", config)
        self.assertFalse(check.run())

    def test_check_passes_empty_source(self):
        """Test the check passes, empty source attribute"""
        config = {"tclass": "infoflow7",
                  "perms": "super_w"}
        check = AssertTE(self.p, "test_check_passes_empty_source", config)
        self.assertFalse(check.run())

    def test_check_passes_empty_target(self):
        """Test the check passes, empty target attribute"""
        config = {"tclass": "infoflow7",
                  "perms": "super_r"}
        check = AssertTE(self.p, "test_check_passes_empty_target", config)
        self.assertFalse(check.run())

    def test_check_passes_exempt_source_type(self):
        """Test the check passes, exempt_source_type"""
        config = {"tclass": "infoflow6",
                  "perms": "hi_w",
                  "exempt_source": "source1"}
        check = AssertTE(self.p, "test_check_passes_exempt_source_type", config)
        self.assertFalse(check.run())

    def test_check_passes_exempt_source_attr(self):
        """Test the check passes, exempt_source_attr"""
        config = {"tclass": "infoflow6",
                  "perms": "hi_r",
                  "exempt_source": "all_sources"}
        check = AssertTE(self.p, "test_check_passes_exempt_source_attr", config)
        self.assertFalse(check.run())

    def test_check_passes_exempt_target_type(self):
        """Test the check passes, exempt_target_type"""
        config = {"tclass": "infoflow5",
                  "perms": "low_w",
                  "exempt_source": "source1"}
        check = AssertTE(self.p, "test_check_passes_exempt_target_type", config)
        self.assertFalse(check.run())

    def test_check_passes_exempt_target_attr(self):
        """Test the check passes, exempt_target_attr"""
        config = {"tclass": "infoflow5",
                  "perms": "low_r",
                  "exempt_target": "all_targets"}
        check = AssertTE(self.p, "test_check_passes_exempt_target_attr", config)
        self.assertFalse(check.run())

    def test_check_passes_expect_source(self):
        """Test the check passes, expect_source"""
        config = {"tclass": "infoflow6",
                  "perms": "hi_r",
                  "expect_source": "source1 source2"}
        check = AssertTE(self.p, "test_check_passes_expect_source", config)
        self.assertFalse(check.run())

    def test_check_passes_expect_source_attr(self):
        """Test the check passes, expect_source with attribute"""
        config = {"tclass": "infoflow4",
                  "perms": "med_w",
                  "expect_source": "all_sources"}
        check = AssertTE(self.p, "test_check_passes_expect_source_attr", config)
        self.assertFalse(check.run())

    def test_check_passes_expect_target(self):
        """Test the check passes, expect_target"""
        config = {"tclass": "infoflow6",
                  "perms": "hi_r",
                  "expect_target": "target1 target2"}
        check = AssertTE(self.p, "test_check_passes_expect_target", config)
        self.assertFalse(check.run())

    def test_check_passes_expect_target_attr(self):
        """Test the check passes, expect_target with attribute"""
        config = {"tclass": "infoflow4",
                  "perms": "med_w",
                  "expect_target": "all_targets"}
        check = AssertTE(self.p, "test_check_passes_expect_target_attr", config)
        self.assertFalse(check.run())

    def test_check_passes_expect_exempt_source(self):
        """"Test the check passes with both expected and exempted sources."""
        config = {"tclass": "infoflow5",
                  "perms": "low_r",
                  "expect_source": "source1",
                  "exempt_source": "source2"}
        check = AssertTE(self.p, "test_check_passes_expect_exempt_source", config)
        self.assertFalse(check.run())

    def test_check_passes_expect_exempt_target(self):
        """"Test the check passes with both expected and exempted targets."""
        config = {"tclass": "infoflow5",
                  "perms": "low_r",
                  "expect_source": "source1",
                  "exempt_source": "source2"}
        check = AssertTE(self.p, "test_check_passes_expect_exempt_target", config)
        self.assertFalse(check.run())

    def test_check_fails(self):
        """Test the check fails"""
        with open("/dev/null", "w") as fd:
            config = {"tclass": "infoflow4",
                      "perms": "med_w",
                      "exempt_source": "source1",
                      "exempt_target": "target2"}
            check = AssertTE(self.p, "test_check_passes_exempt_target_attr", config)
            check.output = fd
            result = check.run()
            self.assertEqual(1, len(result), msg=result)
            self.validate_rule(result[0], TERuletype.allow, "source3", "target3", "infoflow4",
                               set(["med_w"]))

    def test_check_fails_expect_source(self):
        """Test the check fails, expect_source"""
        config = {"tclass": "infoflow7",
                  "perms": "super_w",
                  "expect_source": "source1"}
        check = AssertTE(self.p, "test_check_fails_expect_source", config)
        result = check.run()
        self.assertEqual(1, len(result), msg=result)
        self.assertIn("source1", result[0])

    def test_check_fails_expect_target(self):
        """Test the check fails, expect_target"""
        config = {"tclass": "infoflow7",
                  "perms": "super_r",
                  "expect_target": "target2"}
        check = AssertTE(self.p, "test_check_fails_expect_target", config)
        result = check.run()
        self.assertEqual(1, len(result), msg=result)
        self.assertIn("target2", result[0])
