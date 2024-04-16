# Copyright 2020, Microsoft Corporation
#
# SPDX-License-Identifier: GPL-2.0-only
#
import os

import pytest
import setools


@pytest.mark.obj_args("tests/library/checker/roexec.conf")
class TestReadOnlyExecutables:

    def test_invalid_option(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test invalid option"""
        with pytest.raises(setools.exception.InvalidCheckOption):
            config = {"INVALID": "option"}
            check = setools.checker.roexec.ReadOnlyExecutables(
                compiled_policy, "test_invalid_option", config)

    def test_all_exec(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test all executables are returned for no-option test.."""
        config = dict[str, str]()
        check = setools.checker.roexec.ReadOnlyExecutables(
            compiled_policy, "test_all_exec", config)
        result = check._collect_executables()

        # becasue of unconfined, nonexec is executable
        expected = set(("roexec", "execfile1", "execfile2", "nonexec", "exempt_file"))
        assert expected == set(result.keys())

    def test_exempt_exec_domain(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test for exempting an exec domain."""
        config = {"exempt_exec_domain": "unconfined"}
        check = setools.checker.roexec.ReadOnlyExecutables(
            compiled_policy, "test_exempt_exec_domain", config)
        result = check._collect_executables()

        expected = set(("execfile1", "execfile2", "roexec"))
        assert expected == set(result.keys())

    def test_exempt_file(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test for exempting a file."""
        config = {"exempt_file": "exempt_file"}
        check = setools.checker.roexec.ReadOnlyExecutables(
            compiled_policy, "test_exempt_file", config)
        result = check._collect_executables()

        expected = set(("roexec", "execfile1", "execfile2", "nonexec"))
        assert expected == result.keys()

    def test_exempt_file_attr(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test for exempting a file by attribute."""
        config = {"exempt_file": "exempt_files_attr"}
        check = setools.checker.roexec.ReadOnlyExecutables(
            compiled_policy, "test_exempt_file_attr", config)
        result = check._collect_executables()

        expected = set(("roexec", "nonexec", "exempt_file"))
        assert expected == result.keys()

    def test_fail(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test for failing."""
        with open(os.devnull, "w", encoding="utf-8") as fd:
            config = {"exempt_exec_domain": "unconfined",
                      "exempt_write_domain": "unconfined"}
            check = setools.checker.roexec.ReadOnlyExecutables(
                compiled_policy, "test_fail", config)
            check.output = fd
            result = check.run()

            expected = [compiled_policy.lookup_type("execfile1"),
                        compiled_policy.lookup_type("execfile2")]
            assert expected == result

    def test_pass(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test for passing."""
        with open(os.devnull, "w", encoding="utf-8") as fd:
            config = {"exempt_exec_domain": "unconfined",
                      "exempt_write_domain": "domain1  domain2  unconfined"}
            check = setools.checker.roexec.ReadOnlyExecutables(
                compiled_policy, "test_pass", config)
            check.output = fd
            result = check.run()

            assert not result

    def test_pass2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test for passing with alternate exemptions."""
        with open(os.devnull, "w", encoding="utf-8") as fd:
            config = {"exempt_exec_domain": "unconfined",
                      "exempt_file": "execfile2",
                      "exempt_write_domain": "domain1  unconfined"}
            check = setools.checker.roexec.ReadOnlyExecutables(
                compiled_policy, "test_pass2", config)
            check.output = fd
            result = check.run()

            assert not result
