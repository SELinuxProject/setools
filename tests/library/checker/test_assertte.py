# Copyright 2020, Microsoft Corporation
# Copyright 2020, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: GPL-2.0-only
#

import os

import pytest
import setools


@pytest.mark.obj_args("tests/library/checker/assertte.conf")
class TestAssertTE:

    def test_unconfigured(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test unconfigured."""
        with pytest.raises(setools.exception.InvalidCheckValue):
            config = dict[str, str]()
            check = setools.checker.assertte.AssertTE(compiled_policy, "test_unconfigured", config)

    def test_invalid_option(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test invalid option"""
        with pytest.raises(setools.exception.InvalidCheckOption):
            config = {"INVALID": "option"}
            check = setools.checker.assertte.AssertTE(
                compiled_policy, "test_invalid_option", config)

    def test_source(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test source setting."""
        config = {"source": "src"}
        check = setools.checker.assertte.AssertTE(compiled_policy, "test_source", config)

        expected = compiled_policy.lookup_type("src")
        assert expected == check.source

    def test_source_fail(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test source setting failure."""
        with pytest.raises(setools.exception.InvalidCheckValue):
            config = {"source": "FAIL"}
            check = setools.checker.assertte.AssertTE(compiled_policy, "test_source_fail", config)

    def test_target(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test target setting."""
        config = {"target": "tgt"}
        check = setools.checker.assertte.AssertTE(compiled_policy, "test_target", config)

        expected = compiled_policy.lookup_type("tgt")
        assert expected == check.target

    def test_target_fail(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test target setting failure."""
        with pytest.raises(setools.exception.InvalidCheckValue):
            config = {"target": "FAIL2"}
            check = setools.checker.assertte.AssertTE(compiled_policy, "test_target_fail", config)

    def test_exempt_source(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test exempt_source setting."""
        config = {"source": "system",
                  "exempt_source": " exempt_src1   exempt_src2 "}
        check = setools.checker.assertte.AssertTE(compiled_policy, "test_exempt_source", config)

        # exempt_src2 is an attr
        expected = set((compiled_policy.lookup_type("exempt_src1"),
                        compiled_policy.lookup_type("exempt_source_type")))
        assert expected == check.exempt_source

    def test_source_missing_ignored(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test exempt_source missing type is ignroed."""
        config = {"source": "system",
                  "exempt_source": "FAIL  exempt_src2"}
        check = setools.checker.assertte.AssertTE(
            compiled_policy, "test_source_missing_ignored", config)

        # exempt_src2 is an attr
        expected = set((compiled_policy.lookup_type("exempt_source_type"),))
        assert expected == check.exempt_source

    def test_exempt_target(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test exempt_target setting."""
        config = {"target": "system",
                  "exempt_target": " exempt_tgt1   exempt_tgt2 "}
        check = setools.checker.assertte.AssertTE(compiled_policy, "test_exempt_target", config)

        # exempt_tgt2 is an attr
        expected = set((compiled_policy.lookup_type("exempt_tgt1"),
                        compiled_policy.lookup_type("exempt_target_type")))
        assert expected == check.exempt_target

    def test_target_missing_ignored(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test exempt_target missing type is ignroed."""
        config = {"target": "system",
                  "exempt_target": "FAIL  exempt_tgt2"}
        check = setools.checker.assertte.AssertTE(
            compiled_policy, "test_target_missing_ignored", config)

        # exempt_tgt2 is an attr
        expected = set((compiled_policy.lookup_type("exempt_target_type"),))
        assert expected == check.exempt_target

    def test_expect_source(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test expect_source setting."""
        config = {"tclass": "infoflow3",
                  "expect_source": " exempt_src1   exempt_src2 "}
        check = setools.checker.assertte.AssertTE(compiled_policy, "test_expect_source", config)

        # exempt_src2 is an attr
        expected = set((compiled_policy.lookup_type("exempt_src1"),
                        compiled_policy.lookup_type("exempt_source_type")))
        assert expected == check.expect_source

    def test_expect_source_error(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test bad expect_source setting."""
        with pytest.raises(setools.exception.InvalidCheckValue):
            config = {"tclass": "infoflow3",
                      "expect_source": " source1   INVALID "}
            check = setools.checker.assertte.AssertTE(
                compiled_policy, "test_expect_source_fail", config)

    def test_expect_target(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test expect_target setting."""
        config = {"tclass": "infoflow3",
                  "expect_target": " exempt_tgt1   exempt_tgt2 "}
        check = setools.checker.assertte.AssertTE(compiled_policy, "test_expect_target", config)

        # exempt_tgt2 is an attr
        expected = set((compiled_policy.lookup_type("exempt_tgt1"),
                        compiled_policy.lookup_type("exempt_target_type")))
        assert expected == check.expect_target

    def test_expect_target_error(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test bad expect_target setting."""
        with pytest.raises(setools.exception.InvalidCheckValue):
            config = {"tclass": "infoflow3",
                      "expect_target": " target1   INVALID "}
            check = setools.checker.assertte.AssertTE(
                compiled_policy, "test_expect_target_fail", config)

    def test_tclass(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test tclass setting."""
        config = {"tclass": "infoflow3  infoflow2"}
        check = setools.checker.assertte.AssertTE(compiled_policy, "test_tclass", config)

        expected = set((compiled_policy.lookup_class("infoflow3"),
                        compiled_policy.lookup_class("infoflow2")))
        assert expected == check.tclass

    def test_tclass_fail(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test tclass setting failure."""
        with pytest.raises(setools.exception.InvalidCheckValue):
            config = {"tclass": "FAIL_class"}
            check = setools.checker.assertte.AssertTE(compiled_policy, "test_tclass_fail", config)

    def test_perms(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test perms setting."""
        config = {"perms": " hi_w  super_r "}
        check = setools.checker.assertte.AssertTE(compiled_policy, "test_perms", config)

        expected = set(("hi_w", "super_r"))
        assert expected == check.perms

    def test_perms_fail(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test perms setting failure."""
        with pytest.raises(setools.exception.InvalidCheckValue):
            config = {"perms": "FAIL_perms"}
            check = setools.checker.assertte.AssertTE(compiled_policy, "test_perms_fail", config)

    def test_check_passes(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test the check passes, no matches"""
        config = {"perms": "null"}
        check = setools.checker.assertte.AssertTE(compiled_policy, "test_check_passes", config)
        assert not check.run()

    def test_check_passes_empty_source(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test the check passes, empty source attribute"""
        config = {"tclass": "infoflow7",
                  "perms": "super_w"}
        check = setools.checker.assertte.AssertTE(
            compiled_policy, "test_check_passes_empty_source", config)
        assert not check.run()

    def test_check_passes_empty_target(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test the check passes, empty target attribute"""
        config = {"tclass": "infoflow7",
                  "perms": "super_r"}
        check = setools.checker.assertte.AssertTE(
            compiled_policy, "test_check_passes_empty_target", config)
        assert not check.run()

    def test_check_passes_exempt_source_type(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test the check passes, exempt_source_type"""
        config = {"tclass": "infoflow6",
                  "perms": "hi_w",
                  "exempt_source": "source1"}
        check = setools.checker.assertte.AssertTE(
            compiled_policy, "test_check_passes_exempt_source_type", config)
        assert not check.run()

    def test_check_passes_exempt_source_attr(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test the check passes, exempt_source_attr"""
        config = {"tclass": "infoflow6",
                  "perms": "hi_r",
                  "exempt_source": "all_sources"}
        check = setools.checker.assertte.AssertTE(
            compiled_policy, "test_check_passes_exempt_source_attr", config)
        assert not check.run()

    def test_check_passes_exempt_target_type(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test the check passes, exempt_target_type"""
        config = {"tclass": "infoflow5",
                  "perms": "low_w",
                  "exempt_source": "source1"}
        check = setools.checker.assertte.AssertTE(
            compiled_policy, "test_check_passes_exempt_target_type", config)
        assert not check.run()

    def test_check_passes_exempt_target_attr(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test the check passes, exempt_target_attr"""
        config = {"tclass": "infoflow5",
                  "perms": "low_r",
                  "exempt_target": "all_targets"}
        check = setools.checker.assertte.AssertTE(
            compiled_policy, "test_check_passes_exempt_target_attr", config)
        assert not check.run()

    def test_check_passes_expect_source(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test the check passes, expect_source"""
        config = {"tclass": "infoflow6",
                  "perms": "hi_r",
                  "expect_source": "source1 source2"}
        check = setools.checker.assertte.AssertTE(
            compiled_policy, "test_check_passes_expect_source", config)
        assert not check.run()

    def test_check_passes_expect_source_attr(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test the check passes, expect_source with attribute"""
        config = {"tclass": "infoflow4",
                  "perms": "med_w",
                  "expect_source": "all_sources"}
        check = setools.checker.assertte.AssertTE(
            compiled_policy, "test_check_passes_expect_source_attr", config)
        assert not check.run()

    def test_check_passes_expect_target(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test the check passes, expect_target"""
        config = {"tclass": "infoflow6",
                  "perms": "hi_r",
                  "expect_target": "target1 target2"}
        check = setools.checker.assertte.AssertTE(
            compiled_policy, "test_check_passes_expect_target", config)
        assert not check.run()

    def test_check_passes_expect_target_attr(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test the check passes, expect_target with attribute"""
        config = {"tclass": "infoflow4",
                  "perms": "med_w",
                  "expect_target": "all_targets"}
        check = setools.checker.assertte.AssertTE(
            compiled_policy, "test_check_passes_expect_target_attr", config)
        assert not check.run()

    def test_check_passes_expect_exempt_source(self,
                                               compiled_policy: setools.SELinuxPolicy) -> None:
        """"Test the check passes with both expected and exempted sources."""
        config = {"tclass": "infoflow5",
                  "perms": "low_r",
                  "expect_source": "source1",
                  "exempt_source": "source2"}
        check = setools.checker.assertte.AssertTE(
            compiled_policy, "test_check_passes_expect_exempt_source", config)
        assert not check.run()

    def test_check_passes_expect_exempt_target(self,
                                               compiled_policy: setools.SELinuxPolicy) -> None:
        """"Test the check passes with both expected and exempted targets."""
        config = {"tclass": "infoflow5",
                  "perms": "low_r",
                  "expect_source": "source1",
                  "exempt_source": "source2"}
        check = setools.checker.assertte.AssertTE(
            compiled_policy, "test_check_passes_expect_exempt_target", config)
        assert not check.run()

    def test_check_fails(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test the check fails"""
        with open(os.devnull, "w", encoding="utf-8") as fd:
            config = {"tclass": "infoflow4",
                      "perms": "med_w",
                      "exempt_source": "source1",
                      "exempt_target": "target2"}
            check = setools.checker.assertte.AssertTE(
                compiled_policy, "test_check_passes_exempt_target_attr", config)
            check.output = fd
            result = check.run()
            assert 1 == len(result)
            rule = result.pop()
            assert isinstance(rule, setools.AVRule)
            assert rule.ruletype == setools.TERuletype.allow
            assert rule.source == "source3"
            assert rule.target == "target3"
            assert rule.tclass == "infoflow4"
            assert rule.perms == set(["med_w"])

    def test_check_fails_expect_source(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test the check fails, expect_source"""
        config = {"tclass": "infoflow7",
                  "perms": "super_w",
                  "expect_source": "source1"}
        check = setools.checker.assertte.AssertTE(
            compiled_policy, "test_check_fails_expect_source", config)
        result = check.run()
        assert 1 == len(result)
        msg = result.pop()
        assert isinstance(msg, str)
        assert "source1" in msg

    def test_check_fails_expect_target(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Test the check fails, expect_target"""
        config = {"tclass": "infoflow7",
                  "perms": "super_r",
                  "expect_target": "target2"}
        check = setools.checker.assertte.AssertTE(
            compiled_policy, "test_check_fails_expect_target", config)
        result = check.run()
        msg = result.pop()
        assert isinstance(msg, str)
        assert "target2" in msg
