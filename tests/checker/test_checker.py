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
from unittest.mock import Mock

from ..policyrep.util import compile_policy

from setools.checker import PolicyChecker
from setools.exception import InvalidCheckerConfig, InvalidCheckerModule, InvalidCheckOption, \
    InvalidCheckValue


class PolicyCheckerTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.p = compile_policy("tests/checker/checker.conf")

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.p.path)

    def test_config_empty(self):
        """Test empty config file"""
        with self.assertRaises(InvalidCheckerConfig):
            PolicyChecker(self.p, "/dev/null")

    def test_config_check_missing_type(self):
        """Test check missing check type"""
        with self.assertRaises(InvalidCheckerModule):
            PolicyChecker(self.p, "tests/checker/checker-missingtype.ini")

    def test_config_check_invalid_type(self):
        """Test check invalid check type"""
        with self.assertRaises(InvalidCheckerModule):
            PolicyChecker(self.p, "tests/checker/checker-invalidtype.ini")

    def test_config_check_invalid_option(self):
        """Test check invalid check option"""
        with self.assertRaises(InvalidCheckOption):
            PolicyChecker(self.p, "tests/checker/checker-invalidoption.ini")

    def test_config_check_invalid_value(self):
        """Test check invalid check type"""
        with self.assertRaises(InvalidCheckValue):
            PolicyChecker(self.p, "tests/checker/checker-invalidvalue.ini")

    def test_run_pass(self):
        """Test run with passing config."""
        with open(os.devnull, "w") as fd:
            checker = PolicyChecker(self.p, "tests/checker/checker-valid.ini")

            # create additional disabled mock test
            newcheck = Mock()
            newcheck.checkname = "disabled"
            newcheck.disable = True
            newcheck.validate_config.return_value = None
            newcheck.run.return_value = []
            checker.checks.append(newcheck)

            self.assertEqual(4, len(checker.checks))
            result = checker.run(output=fd)
            self.assertEqual(0, result)
            newcheck.run.assert_not_called()

    def test_run_fail(self):
        """Test run with failing config."""
        with open(os.devnull, "w") as fd:
            checker = PolicyChecker(self.p, "tests/checker/checker-valid.ini")

            # create additional failing mock test
            newcheck = Mock()
            newcheck.checkname = "failing test"
            newcheck.disable = False
            newcheck.validate_config.return_value = None
            newcheck.run.return_value = list(range(13))
            checker.checks.append(newcheck)

            self.assertEqual(4, len(checker.checks))

            result = checker.run(output=fd)
            newcheck.run.assert_called()
            self.assertEqual(13, result)
