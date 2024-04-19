# Copyright 2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: GPL-2.0-only
#
import pytest
import setools


@pytest.mark.obj_args("tests/library/policyrep/common.conf")
class TestCommon:

    def test_string(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Common: string representation"""
        com = list(compiled_policy.commons()).pop()
        assert "infoflow" == str(com), str(com)

    def test_perms(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Common: permissions"""
        com = list(compiled_policy.commons()).pop()
        assert set(["low_w", "low_r"]) == com.perms, com.perms

    def test_statment(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Common: statement."""
        com = list(compiled_policy.commons()).pop()
        assert com.statement() in (
            "common infoflow\n{\n\tlow_w\n\tlow_r\n}",
            "common infoflow\n{\n\tlow_r\n\tlow_w\n}"), \
            com.statement()

    def test_contains(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Common: contains"""
        com = list(compiled_policy.commons()).pop()
        assert "low_r" in com
        assert "med_r" not in com
