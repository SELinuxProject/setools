# Copyright 2020, Microsoft Corporation
#
# SPDX-License-Identifier: GPL-2.0-only
#
import os
from unittest.mock import Mock

import pytest
import setools


@pytest.mark.obj_args("tests/library/checker/checker.conf")
class TestPolicyChecker:

    def test_config_empty(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test empty config file"""
        with pytest.raises(setools.exception.InvalidCheckerConfig):
            setools.checker.PolicyChecker(compiled_policy, os.devnull)

    def test_config_check_missing_type(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test check missing check type"""
        with pytest.raises(setools.exception.InvalidCheckerModule):
            setools.checker.PolicyChecker(compiled_policy,
                                          "tests/library/checker/checker-missingtype.ini")

    def test_config_check_invalid_type(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test check invalid check type"""
        with pytest.raises(setools.exception.InvalidCheckerModule):
            setools.checker.PolicyChecker(compiled_policy,
                                          "tests/library/checker/checker-invalidtype.ini")

    def test_config_check_invalid_option(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test check invalid check option"""
        with pytest.raises(setools.exception.InvalidCheckOption):
            setools.checker.PolicyChecker(compiled_policy,
                                          "tests/library/checker/checker-invalidoption.ini")

    def test_config_check_invalid_value(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test check invalid check type"""
        with pytest.raises(setools.exception.InvalidCheckValue):
            setools.checker.PolicyChecker(compiled_policy,
                                          "tests/library/checker/checker-invalidvalue.ini")

    def test_run_pass(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test run with passing config."""
        with open(os.devnull, "w", encoding="utf-8") as fd:
            checker = setools.checker.PolicyChecker(compiled_policy,
                                                    "tests/library/checker/checker-valid.ini")

            # create additional disabled mock test
            newcheck = Mock()
            newcheck.checkname = "disabled"
            newcheck.disable = True
            newcheck.validate_config.return_value = None
            newcheck.run.return_value = []
            checker.checks.append(newcheck)

            assert 4 == len(checker.checks)
            result = checker.run(output=fd)
            assert 0 == result
            newcheck.run.assert_not_called()

    def test_run_fail(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test run with failing config."""
        with open(os.devnull, "w", encoding="utf-8") as fd:
            checker = setools.checker.PolicyChecker(compiled_policy,
                                                    "tests/library/checker/checker-valid.ini")

            # create additional failing mock test
            newcheck = Mock()
            newcheck.checkname = "failing test"
            newcheck.disable = False
            newcheck.validate_config.return_value = None
            newcheck.run.return_value = list(range(13))
            checker.checks.append(newcheck)

            assert 4 == len(checker.checks)

            result = checker.run(output=fd)
            newcheck.run.assert_called()
            assert 13 == result
