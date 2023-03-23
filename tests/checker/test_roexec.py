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

from setools.checker.roexec import ReadOnlyExecutables
from setools.exception import InvalidCheckOption, InvalidCheckValue


class ReadOnlyExecutablesTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.p = compile_policy("tests/checker/roexec.conf")

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.p.path)

    def test_invalid_option(self):
        """Test invalid option"""
        with self.assertRaises(InvalidCheckOption):
            config = {"INVALID": "option"}
            check = ReadOnlyExecutables(self.p, "test_invalid_option", config)

    def test_all_exec(self):
        """Test all executables are returned for no-option test.."""
        config = {}
        check = ReadOnlyExecutables(self.p, "test_all_exec", config)
        result = check._collect_executables()

        # becasue of unconfined, nonexec is executable
        expected = set(("roexec", "execfile1", "execfile2", "nonexec", "exempt_file"))
        self.assertSetEqual(expected, set(result.keys()))

    def test_exempt_exec_domain(self):
        """Test for exempting an exec domain."""
        config = {"exempt_exec_domain": "unconfined"}
        check = ReadOnlyExecutables(self.p, "test_exempt_exec_domain", config)
        result = check._collect_executables()

        expected = set(("execfile1", "execfile2", "roexec"))
        self.assertSetEqual(expected, set(result.keys()))

    def test_exempt_file(self):
        """Test for exempting a file."""
        config = {"exempt_file": "exempt_file"}
        check = ReadOnlyExecutables(self.p, "test_exempt_file", config)
        result = check._collect_executables()

        expected = set(("roexec", "execfile1", "execfile2", "nonexec"))
        self.assertSetEqual(expected, set(result.keys()))

    def test_exempt_file_attr(self):
        """Test for exempting a file by attribute."""
        config = {"exempt_file": "exempt_files_attr"}
        check = ReadOnlyExecutables(self.p, "test_exempt_file_attr", config)
        result = check._collect_executables()

        expected = set(("roexec", "nonexec", "exempt_file"))
        self.assertSetEqual(expected, set(result.keys()))

    def test_fail(self):
        """Test for failing."""
        with open("/dev/null", "w") as fd:
            config = {"exempt_exec_domain": "unconfined",
                      "exempt_write_domain": "unconfined"}
            check = ReadOnlyExecutables(self.p, "test_fail", config)
            check.output = fd
            result = check.run()

            expected = [self.p.lookup_type("execfile1"),
                        self.p.lookup_type("execfile2")]
            self.assertListEqual(expected, result)

    def test_pass(self):
        """Test for passing."""
        with open("/dev/null", "w") as fd:
            config = {"exempt_exec_domain": "unconfined",
                      "exempt_write_domain": "domain1  domain2  unconfined"}
            check = ReadOnlyExecutables(self.p, "test_pass", config)
            check.output = fd
            result = check.run()

            self.assertFalse(result)

    def test_pass2(self):
        """Test for passing with alternate exemptions."""
        with open("/dev/null", "w") as fd:
            config = {"exempt_exec_domain": "unconfined",
                      "exempt_file": "execfile2",
                      "exempt_write_domain": "domain1  unconfined"}
            check = ReadOnlyExecutables(self.p, "test_pass2", config)
            check.output = fd
            result = check.run()

            self.assertFalse(result)
