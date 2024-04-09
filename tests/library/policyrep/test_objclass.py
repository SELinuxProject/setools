# Copyright 2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: GPL-2.0-only
#
import pytest
import setools


@pytest.mark.obj_args("tests/library/policyrep/objclass.conf")
class TestObjClass:

    def test_string(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """ObjClass: string representation"""
        cls = compiled_policy.lookup_class("infoflow")
        assert "infoflow" == str(cls), str(cls)

    def test_perms(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """ObjClass: permissions"""
        cls = compiled_policy.lookup_class("infoflow8")
        assert frozenset(["super_w", "super_r"]) == cls.perms, f"{cls.perms}"

    def test_statment_wo_common_w_unique(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """ObjClass: statement, no common."""
        cls = compiled_policy.lookup_class("infoflow8")
        assert cls.statement() in (
            "class infoflow8\n{\n\tsuper_w\n\tsuper_r\n}",
            "class infoflow8\n{\n\tsuper_r\n\tsuper_w\n}"), \
            cls.statement()

    def test_statment_w_common_w_unique(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """ObjClass: statement, with common."""
        cls = compiled_policy.lookup_class("infoflow6")
        assert cls.statement() in (
            "class infoflow6\ninherits com_b\n{\n\tperm1\n\tperm2\n}",
            "class infoflow6\ninherits com_b\n{\n\tperm2\n\tperm1\n}"), \
            cls.statement()

    def test_statment_w_common_wo_unique(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """ObjClass: statement, with common, no class perms."""
        cls = compiled_policy.lookup_class("infoflow5")
        assert cls.statement() == "class infoflow5\ninherits com_a\n", cls.statement()

    def test_contains_wo_common(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """ObjClass: contains"""
        cls = compiled_policy.lookup_class("infoflow10")
        assert "read" in cls
        assert "execute" not in cls

    def test_contains_w_common(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """ObjClass: contains, with common"""
        cls = compiled_policy.lookup_class("infoflow4")
        assert "super_both" in cls
        assert "hi_w" in cls
        assert "unmapped" not in cls
