# Copyright 2014, Tresys Technology, LLC
#
# SPDX-License-Identifier: GPL-2.0-only
#
import pytest
import setools


@pytest.mark.obj_args("tests/library/objclassquery.conf")
class TestObjClassQuery:

    def test_unset(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Class query with no criteria."""
        # query with no parameters gets all types.
        classes = sorted(compiled_policy.classes())

        q = setools.ObjClassQuery(compiled_policy)
        q_classes = sorted(q.results())

        assert classes == q_classes

    def test_name_exact(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Class query with exact name match."""
        q = setools.ObjClassQuery(compiled_policy, name="infoflow")

        classes = sorted(str(c) for c in q.results())
        assert ["infoflow"] == classes

    def test_name_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Class query with regex name match."""
        q = setools.ObjClassQuery(compiled_policy, name="infoflow(2|3)", name_regex=True)

        classes = sorted(str(c) for c in q.results())
        assert ["infoflow2", "infoflow3"] == classes

    def test_common_exact(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Class query with exact common name match."""
        q = setools.ObjClassQuery(compiled_policy, common="infoflow")

        classes = sorted(str(c) for c in q.results())
        assert ["infoflow", "infoflow2", "infoflow4", "infoflow7"] == classes

    def test_common_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Class query with regex common name match."""
        q = setools.ObjClassQuery(compiled_policy, common="com_[ab]", common_regex=True)

        classes = sorted(str(c) for c in q.results())
        assert ["infoflow5", "infoflow6"] == classes

    def test_perm_indirect_intersect(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Class query with indirect, intersect permission name patch."""
        q = setools.ObjClassQuery(
            compiled_policy, perms=set(["send"]), perms_indirect=True, perms_equal=False)

        classes = sorted(str(c) for c in q.results())
        assert ["infoflow6"] == classes

    def test_perm_direct_intersect(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Class query with direct, intersect permission name patch."""
        q = setools.ObjClassQuery(
            compiled_policy, perms=set(["super_r"]), perms_indirect=False, perms_equal=False)

        classes = sorted(str(c) for c in q.results())
        assert ["infoflow2", "infoflow4", "infoflow8"] == classes

    def test_perm_indirect_equal(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Class query with indirect, equal permission name patch."""
        q = setools.ObjClassQuery(compiled_policy, perms=set(
            ["low_w", "med_w", "hi_w", "low_r", "med_r", "hi_r", "unmapped"]),
            perms_indirect=True, perms_equal=True)

        classes = sorted(str(c) for c in q.results())
        assert ["infoflow7"] == classes

    def test_perm_direct_equal(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Class query with direct, equal permission name patch."""
        q = setools.ObjClassQuery(compiled_policy, perms=set(
            ["super_r", "super_w"]), perms_indirect=False, perms_equal=True)

        classes = sorted(str(c) for c in q.results())
        assert ["infoflow2", "infoflow8"] == classes

    def test_perm_indirect_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Class query with indirect, regex permission name patch."""
        q = setools.ObjClassQuery(
            compiled_policy, perms="(send|setattr)", perms_indirect=True, perms_regex=True)

        classes = sorted(str(c) for c in q.results())
        assert ["infoflow6", "infoflow9"] == classes

    def test_perm_direct_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Class query with direct, regex permission name patch."""
        q = setools.ObjClassQuery(
            compiled_policy, perms="(read|super_r)", perms_indirect=False, perms_regex=True)

        classes = sorted(str(c) for c in q.results())
        assert ["infoflow10", "infoflow2", "infoflow4", "infoflow8"] == classes
