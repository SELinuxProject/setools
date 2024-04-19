# Copyright 2020, Microsoft Corporation
# Copyright 2020, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: GPL-2.0-only
#
import os

import pytest
import setools


@pytest.mark.obj_args("tests/library/checker/assertrbac.conf")
class TestAssertRBAC:

    def test_unconfigured(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test unconfigured."""
        with pytest.raises(setools.exception.InvalidCheckValue):
            config: dict[str, str] = {}
            check = setools.checker.assertrbac.AssertRBAC(
                compiled_policy, "test_unconfigured", config)

    def test_invalid_option(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test invalid option"""
        with pytest.raises(setools.exception.InvalidCheckOption):
            config = {"INVALID": "option"}
            check = setools.checker.assertrbac.AssertRBAC(
                compiled_policy, "test_invalid_option", config)

    def test_source(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test source setting."""
        config = {"source": "src"}
        check = setools.checker.assertrbac.AssertRBAC(compiled_policy, "test_source", config)
        expected = compiled_policy.lookup_role("src")
        assert expected == check.source

    def test_source_error(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test source bad setting."""
        with pytest.raises(setools.exception.InvalidCheckValue):
            config = {"source": "FAIL"}
            check = setools.checker.assertrbac.AssertRBAC(
                compiled_policy, "test_source_fail", config)

    def test_target(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test target setting."""
        config = {"target": "tgt"}
        check = setools.checker.assertrbac.AssertRBAC(compiled_policy, "test_target", config)
        expected = compiled_policy.lookup_role("tgt")
        assert expected == check.target

    def test_target_error(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test target bad setting."""
        with pytest.raises(setools.exception.InvalidCheckValue):
            config = {"target": "FAIL2"}
            check = setools.checker.assertrbac.AssertRBAC(
                compiled_policy, "test_target_fail", config)

    def test_exempt_source(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test exempt_source setting."""
        config = {"source": "system",
                  "exempt_source": " exempt_src1   exempt_src2 "}
        check = setools.checker.assertrbac.AssertRBAC(
            compiled_policy, "test_exempt_source", config)

        # exempt_src2 is an attr
        expected = set((compiled_policy.lookup_role("exempt_src1"),
                        compiled_policy.lookup_role("exempt_src2")))
        assert expected == check.exempt_source

    def test_exempt_source_missing(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test exempt_source missing role is ignroed."""
        config = {"source": "system",
                  "exempt_source": "FAIL  exempt_src2"}
        check = setools.checker.assertrbac.AssertRBAC(
            compiled_policy, "test_source_missing_ignored", config)

        # exempt_src2 is an attr
        expected = set((compiled_policy.lookup_role("exempt_src2"),))
        assert expected == check.exempt_source

    def test_exempt_target(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test exempt_target setting."""
        config = {"target": "system",
                  "exempt_target": " exempt_tgt1   exempt_tgt2 "}
        check = setools.checker.assertrbac.AssertRBAC(
            compiled_policy, "test_exempt_target", config)

        # exempt_tgt2 is an attr
        expected = set((compiled_policy.lookup_role("exempt_tgt1"),
                        compiled_policy.lookup_role("exempt_tgt2")))
        assert expected == check.exempt_target

    def test_exempt_target_missing(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Success, missing role ignored"""
        config = {"target": "system",
                  "exempt_target": "FAIL  exempt_tgt2"}
        check = setools.checker.assertrbac.AssertRBAC(
            compiled_policy, "test_target_missing_ignored", config)

        # exempt_tgt2 is an attr
        expected = set((compiled_policy.lookup_role("exempt_tgt2"),))
        assert expected == check.exempt_target

    def test_expect_source(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test expect_source setting."""
        config = {"target": "tgt",
                  "expect_source": " exempt_src1   exempt_src2 "}
        check = setools.checker.assertrbac.AssertRBAC(
            compiled_policy, "test_expect_source", config)

        # exempt_src2 is an attr
        expected = set((compiled_policy.lookup_role("exempt_src1"),
                        compiled_policy.lookup_role("exempt_src2")))
        assert expected == check.expect_source

    def test_expect_source_error(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test bad expect_source setting."""
        with pytest.raises(setools.exception.InvalidCheckValue):
            config = {"target": "tgt",
                      "expect_source": " source1   INVALID "}
            check = setools.checker.assertrbac.AssertRBAC(
                compiled_policy, "test_expect_source_fail", config)

    def test_expect_target(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test expect_target setting."""
        config = {"source": "src",
                  "expect_target": " exempt_tgt1   exempt_tgt2 "}
        check = setools.checker.assertrbac.AssertRBAC(
            compiled_policy, "test_expect_target", config)

        # exempt_tgt2 is an attr
        expected = set((compiled_policy.lookup_role("exempt_tgt1"),
                        compiled_policy.lookup_role("exempt_tgt2")))
        assert expected == check.expect_target

    def test_expect_target_error(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test bad expect_target setting."""
        with pytest.raises(setools.exception.InvalidCheckValue):
            config = {"source": "src",
                      "expect_target": " target1   INVALID "}
            check = setools.checker.assertrbac.AssertRBAC(
                compiled_policy, "test_expect_target_fail", config)

    def test_check_passes(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test the check passes, no matches"""
        config = {"source": "src",
                  "target": "tgt"}
        check = setools.checker.assertrbac.AssertRBAC(compiled_policy, "test_check_passes", config)
        assert not check.run()

    def test_check_passes_exempt_source_role(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test the check passes, exempt_source_role"""
        config = {"target": "target1",
                  "exempt_source": "source1"}
        check = setools.checker.assertrbac.AssertRBAC(
            compiled_policy, "test_check_passes_exempt_source_role", config)
        assert not check.run()

    def test_check_passes_exempt_target_role(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test the check passes, exempt_target_role"""
        config = {"target": "target2",
                  "exempt_source": "source2"}
        check = setools.checker.assertrbac.AssertRBAC(
            compiled_policy, "test_check_passes_exempt_target_role", config)
        assert not check.run()

    def test_check_passes_expect_source(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test the check passes, expect_source"""
        config = {"target": "target3",
                  "expect_source": "source3a source3b"}
        check = setools.checker.assertrbac.AssertRBAC(
            compiled_policy, "test_check_passes_expect_source", config)
        assert not check.run()

    def test_check_passes_expect_target(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test the check passes, expect_target"""
        config = {"source": "source4",
                  "expect_target": "target4a target4b"}
        check = setools.checker.assertrbac.AssertRBAC(
            compiled_policy, "test_check_passes_expect_target", config)
        assert not check.run()

    def test_check_passes_expect_exempt_source(self,
                                               compiled_policy: setools.SELinuxPolicy) -> None:
        """"Test the check passes with both expected and exempted sources."""
        config = {"target": "target5",
                  "expect_source": "source5a",
                  "exempt_source": "source5b"}
        check = setools.checker.assertrbac.AssertRBAC(
            compiled_policy, "test_check_passes_expect_exempt_source", config)
        assert not check.run()

    def test_check_passes_expect_exempt_target(self,
                                               compiled_policy: setools.SELinuxPolicy) -> None:
        """"Test the check passes with both expected and exempted targets."""
        config = {"source": "source6",
                  "expect_target": "target6a",
                  "exempt_target": "target6b"}
        check = setools.checker.assertrbac.AssertRBAC(
            compiled_policy, "test_check_passes_expect_exempt_target", config)
        assert not check.run()

    def test_check_fails(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test the check fails"""
        with open(os.devnull, "w", encoding="utf-8") as fd:
            config = {"source": "source7",
                      "expect_target": "target7a",
                      "exempt_target": "target7b"}
            check = setools.checker.assertrbac.AssertRBAC(
                compiled_policy, "test_check_passes_exempt_target_attr", config)
            check.output = fd
            result = check.run()
            assert 1 == len(result)
            rule = result[0]
            assert isinstance(rule, setools.RoleAllow)
            assert setools.RBACRuletype.allow == rule.ruletype
            assert "source7" == rule.source
            assert "target7c" == rule.target

    def test_check_fails_expect_source(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test the check fails, expect_source"""
        config = {"target": "target8",
                  "expect_source": "source8"}
        check = setools.checker.assertrbac.AssertRBAC(
            compiled_policy, "test_check_fails_expect_source", config)
        result = check.run()
        assert 1 == len(result)
        msg = result.pop()
        assert isinstance(msg, str)
        assert "source8" in msg

    def test_check_fails_expect_target(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test the check fails, expect_target"""
        config = {"source": "source9",
                  "expect_target": "target9"}
        check = setools.checker.assertrbac.AssertRBAC(
            compiled_policy, "test_check_fails_expect_target", config)
        result = check.run()
        assert 1 == len(result)
        msg = result.pop()
        assert isinstance(msg, str)
        assert "target9" in msg
