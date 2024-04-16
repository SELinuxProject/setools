# Copyright 2020, Microsoft Corporation
#
# SPDX-License-Identifier: GPL-2.0-only
#
import os

import pytest
import setools


@pytest.mark.obj_args("tests/library/checker/emptyattr.conf")
class TestEmptyTypeAttr:

    def test_invalid_option(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test invalid option"""
        with pytest.raises(setools.exception.InvalidCheckOption):
            config = {"INVALID": "option"}
            check = setools.checker.emptyattr.EmptyTypeAttr(
                compiled_policy, "test_invalid_option", config)

    def test_attr_setting(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """EmptyTypeAttr test attr setting."""
        config = {"attr": "test1"}
        check = setools.checker.emptyattr.EmptyTypeAttr(
            compiled_policy, "test_attr_setting", config)

        expected = compiled_policy.lookup_typeattr("test1")
        assert expected == check.attr

    def test_attr_setting_fail(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """EmptyTypeAttr test attr setting with invalid attr."""
        with pytest.raises(setools.exception.InvalidCheckValue):
            config = {"attr": "FAILATTR"}
            check = setools.checker.emptyattr.EmptyTypeAttr(
                compiled_policy, "test_attr_setting_fail", config)

    def test_attr_setting_missing(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """EmptyTypeAttr test attr setting missing."""
        with pytest.raises(setools.exception.InvalidCheckValue):
            config = dict[str, str]()
            check = setools.checker.emptyattr.EmptyTypeAttr(
                compiled_policy, "test_attr_setting_missing", config)

    def test_missingok_setting(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """EmptyTypeAttr test missing_ok setting."""
        config = {"attr": "test1",
                  "missing_ok": "true"}
        check = setools.checker.emptyattr.EmptyTypeAttr(
            compiled_policy, "test_missingok_setting", config)
        assert check.missing_ok

        config = {"attr": "test1",
                  "missing_ok": " YeS "}
        check = setools.checker.emptyattr.EmptyTypeAttr(
            compiled_policy, "test_missingok_setting", config)
        assert check.missing_ok

        config = {"attr": "test1",
                  "missing_ok": " 1 "}
        check = setools.checker.emptyattr.EmptyTypeAttr(
            compiled_policy, "test_missingok_setting", config)
        assert check.missing_ok

        config = {"attr": "test1",
                  "missing_ok": " No "}
        check = setools.checker.emptyattr.EmptyTypeAttr(
            compiled_policy, "test_missingok_setting", config)
        assert not check.missing_ok

    def test_pass(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """EmptyTypeAttr test pass."""
        with open(os.devnull, "w", encoding="utf-8") as fd:
            config = {"attr": "test1"}
            check = setools.checker.emptyattr.EmptyTypeAttr(compiled_policy, "test_pass", config)
            check.output = fd
            result = check.run()
            assert 0 == len(result)

    def test_pass_missingok(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """EmptyTypeAttr test pass by missing."""
        with open(os.devnull, "w", encoding="utf-8") as fd:
            config = {"attr": "test2",
                      "missing_ok": "true"}
            check = setools.checker.emptyattr.EmptyTypeAttr(
                compiled_policy, "test_pass_missingok", config)
            check.output = fd
            result = check.run()
            assert 0 == len(result)

    def test_fail(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """EmptyTypeAttr test fail."""
        with open(os.devnull, "w", encoding="utf-8") as fd:
            # also verify missing_ok doesn't induce a pass
            # when the attr exists
            config = {"attr": "test3",
                      "missing_ok": "true"}
            check = setools.checker.emptyattr.EmptyTypeAttr(compiled_policy, "test_fail", config)
            check.output = fd
            result = check.run()
            expected = [compiled_policy.lookup_type("test3_hit1"),
                        compiled_policy.lookup_type("test3_hit2")]
            assert expected == result
