# Copyright 2020, 2025, Microsoft Corporation
#
# SPDX-License-Identifier: GPL-2.0-only
#
import os

import pytest
import setools


@pytest.mark.obj_args("tests/library/checker/rokmod.conf")
class TestReadOnlyKernelModules:

    def test_invalid_option(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test invalid option"""
        with pytest.raises(setools.exception.InvalidCheckOption):
            config = {"INVALID": "option"}
            check = setools.checker.rokmod.ReadOnlyKernelModules(
                compiled_policy, "test_invalid_option", config)

    def test_all_mods(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test all modules are returned for no-option test.."""
        config = dict[str, str]()
        check = setools.checker.rokmod.ReadOnlyKernelModules(
            compiled_policy, "test_all_mods", config)
        result = check._collect_kernel_mods()

        # because of unconfined, nonkmod is loadable
        expected = set(("rokmod", "kmodfile1", "kmodfile2", "nonkmod", "exempt_file"))
        assert expected == set(result.keys())

    def test_exempt_load_domain(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test for exempting a loading domain."""
        config = {"exempt_load_domain": "unconfined"}
        check = setools.checker.rokmod.ReadOnlyKernelModules(
            compiled_policy, "test_exempt_load_domain", config)
        result = check._collect_kernel_mods()

        expected = set(("kmodfile1", "kmodfile2", "rokmod"))
        assert expected == set(result.keys())

    def test_exempt_file(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test for exempting a file."""
        config = {"exempt_file": "exempt_file"}
        check = setools.checker.rokmod.ReadOnlyKernelModules(
            compiled_policy, "test_exempt_file", config)
        result = check._collect_kernel_mods()

        expected = set(("rokmod", "kmodfile1", "kmodfile2", "nonkmod"))
        assert expected == result.keys()

    def test_exempt_file_attr(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test for exempting a file by attribute."""
        config = {"exempt_file": "exempt_files_attr"}
        check = setools.checker.rokmod.ReadOnlyKernelModules(
            compiled_policy, "test_exempt_file_attr", config)
        result = check._collect_kernel_mods()

        expected = set(("rokmod", "nonkmod", "exempt_file"))
        assert expected == result.keys()

    def test_fail(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test for failing."""
        with open(os.devnull, "w", encoding="utf-8") as fd:
            config = {"exempt_load_domain": "unconfined",
                      "exempt_write_domain": "unconfined"}
            check = setools.checker.rokmod.ReadOnlyKernelModules(
                compiled_policy, "test_fail", config)
            check.output = fd
            result = check.run()

            expected = [compiled_policy.lookup_type("kmodfile1"),
                        compiled_policy.lookup_type("kmodfile2")]
            assert expected == result

    def test_pass(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test for passing."""
        with open(os.devnull, "w", encoding="utf-8") as fd:
            config = {"exempt_load_domain": "unconfined",
                      "exempt_write_domain": "domain1  domain2  unconfined"}
            check = setools.checker.rokmod.ReadOnlyKernelModules(
                compiled_policy, "test_pass", config)
            check.output = fd
            result = check.run()

            assert not result

    def test_pass2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test for passing with alternate exemptions."""
        with open(os.devnull, "w", encoding="utf-8") as fd:
            config = {"exempt_load_domain": "unconfined",
                      "exempt_file": "kmodfile2",
                      "exempt_write_domain": "domain1  unconfined"}
            check = setools.checker.rokmod.ReadOnlyKernelModules(
                compiled_policy, "test_pass2", config)
            check.output = fd
            result = check.run()

            assert not result
