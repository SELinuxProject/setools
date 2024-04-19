"""Type enforcement rule query unit tests."""
# Copyright 2014, Tresys Technology, LLC
#
# SPDX-License-Identifier: GPL-2.0-only
#
# pylint: disable=invalid-name,too-many-public-methods
import pytest
import setools
from setools import TERuleQuery
from setools import TERuletype as TRT

from . import util


@pytest.mark.obj_args("tests/library/terulequery.conf")
class TestTERuleQuery:

    """Type enforcement rule query unit tests."""

    def test_unset(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """TE rule query with no criteria."""
        # query with no parameters gets all TE rules.
        rules = sorted(compiled_policy.terules())

        q = TERuleQuery(compiled_policy)
        q_rules = sorted(q.results())

        assert rules == q_rules

    def test_source_direct(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """TE rule query with exact, direct, source match."""
        q = TERuleQuery(
            compiled_policy, source="test1a", source_indirect=False, source_regex=False)

        r = sorted(q.results())
        assert len(r) == 1
        util.validate_rule(r[0], TRT.allow, "test1a", "test1t", "infoflow", set(["hi_w"]))

    def test_source_indirect(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """TE rule query with exact, indirect, source match."""
        q = TERuleQuery(
            compiled_policy, source="test2s", source_indirect=True, source_regex=False)

        r = sorted(q.results())
        assert len(r) == 1
        util.validate_rule(r[0], TRT.allow, "test2a", "test2t", "infoflow", set(["hi_w"]))

    def test_source_direct_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """TE rule query with regex, direct, source match."""
        q = TERuleQuery(
            compiled_policy, source="test3a.*", source_indirect=False, source_regex=True)

        r = sorted(q.results())
        assert len(r) == 1
        util.validate_rule(r[0], TRT.allow, "test3aS", "test3t", "infoflow", set(["low_r"]))

    def test_source_indirect_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """TE rule query with regex, indirect, source match."""
        q = TERuleQuery(
            compiled_policy, source="test4(s|t)", source_indirect=True, source_regex=True)

        r = sorted(q.results())
        assert len(r) == 2
        util.validate_rule(r[0], TRT.allow, "test4a1", "test4a1", "infoflow", set(["hi_w"]))
        util.validate_rule(r[1], TRT.allow, "test4a2", "test4a2", "infoflow", set(["low_r"]))

    def test_target_direct(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """TE rule query with exact, direct, target match."""
        q = TERuleQuery(
            compiled_policy, target="test5a", target_indirect=False, target_regex=False)

        r = sorted(q.results())
        assert len(r) == 1
        util.validate_rule(r[0], TRT.allow, "test5s", "test5a", "infoflow", set(["hi_w"]))

    def test_target_indirect(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """TE rule query with exact, indirect, target match."""
        q = TERuleQuery(
            compiled_policy, target="test6t", target_indirect=True, target_regex=False)

        r = sorted(q.results())
        assert len(r) == 2
        util.validate_rule(r[0], TRT.allow, "test6s", "test6a", "infoflow", set(["hi_w"]))
        util.validate_rule(r[1], TRT.allow, "test6s", "test6t", "infoflow", set(["low_r"]))

    def test_target_direct_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """TE rule query with regex, direct, target match."""
        q = TERuleQuery(
            compiled_policy, target="test7a.*", target_indirect=False, target_regex=True)

        r = sorted(q.results())
        assert len(r) == 1
        util.validate_rule(r[0], TRT.allow, "test7s", "test7aPASS", "infoflow", set(["low_r"]))

    def test_target_indirect_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """TE rule query with regex, indirect, target match."""
        q = TERuleQuery(
            compiled_policy, target="test8(s|t)", target_indirect=True, target_regex=True)

        r = sorted(q.results())
        assert len(r) == 2
        util.validate_rule(r[0], TRT.allow, "test8a1", "test8a1", "infoflow", set(["hi_w"]))
        util.validate_rule(r[1], TRT.allow, "test8a2", "test8a2", "infoflow", set(["low_r"]))

    def test_class_list(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """TE rule query with object class list match."""
        q = TERuleQuery(
            compiled_policy, tclass=["infoflow3", "infoflow4"], tclass_regex=False)

        r = sorted(q.results())
        assert len(r) == 2
        util.validate_rule(r[0], TRT.allow, "test10", "test10", "infoflow3", set(["null"]))
        util.validate_rule(r[1], TRT.allow, "test10", "test10", "infoflow4", set(["hi_w"]))

    def test_class_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """TE rule query with object class regex match."""
        q = TERuleQuery(compiled_policy, tclass="infoflow(5|6)", tclass_regex=True)

        r = sorted(q.results())
        assert len(r) == 2
        util.validate_rule(r[0], TRT.allow, "test11", "test11", "infoflow5", set(["low_w"]))
        util.validate_rule(r[1], TRT.allow, "test11", "test11", "infoflow6", set(["med_r"]))

    def test_perms_any(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """TE rule query with permission set intersection."""
        q = TERuleQuery(compiled_policy, perms=["super_r"], perms_equal=False)

        r = sorted(q.results())
        assert len(r) == 2
        util.validate_rule(r[0], TRT.allow, "test12a", "test12a", "infoflow7", set(["super_r"]))
        util.validate_rule(r[1], TRT.allow, "test12b", "test12b", "infoflow7",
                           set(["super_r", "super_none"]))

    def test_perms_equal(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """TE rule query with permission set equality."""
        q = TERuleQuery(
            compiled_policy, perms=["super_w", "super_none", "super_both"], perms_equal=True)

        r = sorted(q.results())
        assert len(r) == 1
        util.validate_rule(r[0], TRT.allow, "test13c", "test13c", "infoflow7",
                           set(["super_w", "super_none", "super_both"]))

    def test_ruletype(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """TE rule query with rule type match."""
        q = TERuleQuery(compiled_policy, ruletype=["auditallow", "dontaudit"])

        r = sorted(q.results())
        assert len(r) == 2
        util.validate_rule(r[0], TRT.auditallow, "test14", "test14", "infoflow7",
                           set(["super_both"]))
        util.validate_rule(r[1], TRT.dontaudit, "test14", "test14", "infoflow7",
                           set(["super_unmapped"]))

    def test_perms_subset1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """TE rule query with permission subset."""
        q = TERuleQuery(compiled_policy, perms=["super_none", "super_both"], perms_subset=True)

        r = sorted(q.results())
        assert len(r) == 2
        util.validate_rule(r[0], TRT.allow, "test13c", "test13c", "infoflow7",
                           set(["super_w", "super_none", "super_both"]))
        util.validate_rule(r[1], TRT.allow, "test13d", "test13d", "infoflow7",
                           set(["super_w", "super_none", "super_both", "super_unmapped"]))

    def test_perms_subset2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """TE rule query with permission subset (equality)."""
        q = TERuleQuery(compiled_policy, perms=["super_w", "super_none", "super_both",
                                                "super_unmapped"],
                        perms_subset=True)

        r = sorted(q.results())
        assert len(r) == 1
        util.validate_rule(r[0], TRT.allow, "test13d", "test13d", "infoflow7",
                           set(["super_w", "super_none", "super_both", "super_unmapped"]))

    def test_default(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """TE rule query with default type exact match."""
        q = TERuleQuery(compiled_policy, default="test100d", default_regex=False)

        r = sorted(q.results())
        assert len(r) == 1
        util.validate_rule(r[0], TRT.type_transition, "test100", "test100", "infoflow7", "test100d")

    def test_default_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """TE rule query with default type regex match."""
        q = TERuleQuery(compiled_policy, default="test101.", default_regex=True)

        r = sorted(q.results())
        assert len(r) == 2
        util.validate_rule(r[0], TRT.type_transition, "test101", "test101d", "infoflow7",
                           "test101e")
        util.validate_rule(r[1], TRT.type_transition, "test101", "test101e", "infoflow7",
                           "test101d")

    def test_boolean_intersection(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """TE rule query with intersection Boolean set match."""
        q = TERuleQuery(compiled_policy, boolean=["test200"])

        r = sorted(q.results())
        assert len(r) == 2
        util.validate_rule(r[0], TRT.allow, "test200t1", "test200t1", "infoflow7",
                           set(["super_w"]), cond="test200")
        util.validate_rule(r[1], TRT.allow, "test200t2", "test200t2", "infoflow7",
                           set(["super_w"]), cond="test200a && test200")

    def test_boolean_equal(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """TE rule query with equal Boolean set match."""
        q = TERuleQuery(compiled_policy, boolean=["test201a", "test201b"], boolean_equal=True)

        r = sorted(q.results())
        assert len(r) == 1
        util.validate_rule(r[0], TRT.allow, "test201t1", "test201t1", "infoflow7",
                           set(["super_unmapped"]), cond="test201b && test201a")

    def test_boolean_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """TE rule query with regex Boolean match."""
        q = TERuleQuery(compiled_policy, boolean="test202(a|b)", boolean_regex=True)

        r = sorted(q.results())
        assert len(r) == 2
        util.validate_rule(r[0], TRT.allow, "test202t1", "test202t1", "infoflow7",
                           set(["super_none"]), cond="test202a")
        util.validate_rule(r[1], TRT.allow, "test202t2", "test202t2", "infoflow7",
                           set(["super_unmapped"]), cond="test202b || test202c")

    def test_issue111(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """TE rule query with attribute source criteria, indirect match."""
        # https://github.com/TresysTechnology/setools/issues/111
        q = TERuleQuery(compiled_policy, source="test300b", source_indirect=True)

        r = sorted(q.results())
        assert len(r) == 4
        util.validate_rule(r[0], TRT.allow, "test300a", "test300target", "infoflow7", set(["hi_w"]))
        util.validate_rule(r[1], TRT.allow, "test300b", "test300target", "infoflow7",
                           set(["super_w"]))
        util.validate_rule(r[2], TRT.allow, "test300t1", "test300t1", "infoflow7", set(["hi_r"]))
        util.validate_rule(r[3], TRT.allow, "test300t2", "test300t2", "infoflow7", set(["med_w"]))

    def test_issue111_2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """TE rule query with attribute target criteria, indirect match."""
        # https://github.com/TresysTechnology/setools/issues/111
        q = TERuleQuery(compiled_policy, target="test301b", target_indirect=True)

        r = sorted(q.results())
        assert len(r) == 4
        util.validate_rule(r[0], TRT.allow, "test301source", "test301a", "infoflow7", set(["hi_w"]))
        util.validate_rule(r[1], TRT.allow, "test301source", "test301b", "infoflow7",
                           set(["super_w"]))
        util.validate_rule(r[2], TRT.allow, "test301t1", "test301t1", "infoflow7", set(["hi_r"]))
        util.validate_rule(r[3], TRT.allow, "test301t2", "test301t2", "infoflow7", set(["med_w"]))

    def test_issue111_3(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """TE rule query with attribute default type criteria."""
        # https://github.com/TresysTechnology/setools/issues/111
        q = TERuleQuery(compiled_policy, default="test302")

        r = sorted(q.results())
        assert len(r) == 2
        util.validate_rule(r[0], TRT.type_transition, "test302source", "test302t1", "infoflow7",
                           "test302t1")
        util.validate_rule(r[1], TRT.type_transition, "test302source", "test302t2", "infoflow7",
                           "test302t2")


@pytest.mark.obj_args("tests/library/terulequery2.conf")
class TERuleQueryXperm:

    """TE Rule Query with extended permission rules."""

    def test_source_direct(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Xperm rule query with exact, direct, source match."""
        q = TERuleQuery(
            compiled_policy, source="test1a", source_indirect=False, source_regex=False)

        r = sorted(q.results())
        assert len(r) == 1
        util.validate_rule(r[0], TRT.allowxperm, "test1a", "test1t", "infoflow",
                           setools.IoctlSet(range(0xebe0, 0xebff + 1)), xperm="ioctl")

    def test_source_indirect(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Xperm rule query with exact, indirect, source match."""
        q = TERuleQuery(
            compiled_policy, source="test2s", source_indirect=True, source_regex=False)

        r = sorted(q.results())
        assert len(r) == 1
        util.validate_rule(r[0], TRT.allowxperm, "test2a", "test2t", "infoflow",
                           setools.IoctlSet([0x5411, 0x5451]), xperm="ioctl")

    def test_source_direct_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Xperm rule query with regex, direct, source match."""
        q = TERuleQuery(
            compiled_policy, source="test3a.*", source_indirect=False, source_regex=True)

        r = sorted(q.results())
        assert len(r) == 1
        util.validate_rule(r[0], TRT.allowxperm, "test3aS", "test3t", "infoflow",
                           setools.IoctlSet([0x1111]), xperm="ioctl")

    def test_source_indirect_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Xperm rule query with regex, indirect, source match."""
        q = TERuleQuery(
            compiled_policy, source="test4(s|t)", source_indirect=True, source_regex=True)

        r = sorted(q.results())
        assert len(r) == 2
        util.validate_rule(r[0], TRT.allowxperm, "test4a1", "test4a1", "infoflow",
                           setools.IoctlSet([0x9999]), xperm="ioctl")
        util.validate_rule(r[1], TRT.allowxperm, "test4a2", "test4a2", "infoflow",
                           setools.IoctlSet([0x1111]), xperm="ioctl")

    def test_target_direct(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Xperm rule query with exact, direct, target match."""
        q = TERuleQuery(
            compiled_policy, target="test5a", target_indirect=False, target_regex=False)

        r = sorted(q.results())
        assert len(r) == 1
        util.validate_rule(r[0], TRT.allowxperm, "test5s", "test5a", "infoflow",
                           setools.IoctlSet([0x9999]), xperm="ioctl")

    def test_target_indirect(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Xperm rule query with exact, indirect, target match."""
        q = TERuleQuery(
            compiled_policy, target="test6t", target_indirect=True, target_regex=False)

        r = sorted(q.results())
        assert len(r) == 2
        util.validate_rule(r[0], TRT.allowxperm, "test6s", "test6a", "infoflow",
                           setools.IoctlSet([0x9999]), xperm="ioctl")
        util.validate_rule(r[1], TRT.allowxperm, "test6s", "test6t", "infoflow",
                           setools.IoctlSet([0x1111]), xperm="ioctl")

    def test_target_direct_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Xperm rule query with regex, direct, target match."""
        q = TERuleQuery(
            compiled_policy, target="test7a.*", target_indirect=False, target_regex=True)

        r = sorted(q.results())
        assert len(r) == 1
        util.validate_rule(r[0], TRT.allowxperm, "test7s", "test7aPASS", "infoflow",
                           setools.IoctlSet([0x1111]), xperm="ioctl")

    def test_target_indirect_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Xperm rule query with regex, indirect, target match."""
        q = TERuleQuery(
            compiled_policy, target="test8(s|t)", target_indirect=True, target_regex=True)

        r = sorted(q.results())
        assert len(r) == 2
        util.validate_rule(r[0], TRT.allowxperm, "test8a1", "test8a1", "infoflow",
                           setools.IoctlSet([0x9999]), xperm="ioctl")
        util.validate_rule(r[1], TRT.allowxperm, "test8a2", "test8a2", "infoflow",
                           setools.IoctlSet([0x1111]), xperm="ioctl")

    def test_class_list(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Xperm rule query with object class list match."""
        q = TERuleQuery(
            compiled_policy, tclass=["infoflow3", "infoflow4"], tclass_regex=False)

        r = sorted(q.results())
        assert len(r) == 2
        util.validate_rule(r[0], TRT.allowxperm, "test10", "test10", "infoflow3",
                           setools.IoctlSet([0]), xperm="ioctl")
        util.validate_rule(r[1], TRT.allowxperm, "test10", "test10", "infoflow4",
                           setools.IoctlSet([0x9999]), xperm="ioctl")

    def test_class_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Xperm rule query with object class regex match."""
        q = TERuleQuery(compiled_policy, tclass="infoflow(5|6)", tclass_regex=True)

        r = sorted(q.results())
        assert len(r) == 2
        util.validate_rule(r[0], TRT.allowxperm, "test11", "test11", "infoflow5",
                           setools.IoctlSet([0x1111]), xperm="ioctl")
        util.validate_rule(r[1], TRT.allowxperm, "test11", "test11", "infoflow6",
                           setools.IoctlSet([0x5555]), xperm="ioctl")

    def test_ruletype(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Xperm rule query with rule type match."""
        q = TERuleQuery(compiled_policy, ruletype=["auditallowxperm", "dontauditxperm"])

        r = sorted(q.results())
        assert len(r) == 2
        util.validate_rule(r[0], TRT.auditallowxperm, "test14", "test14", "infoflow7",
                           setools.IoctlSet([0x1234]), xperm="ioctl")
        util.validate_rule(r[1], TRT.dontauditxperm, "test14", "test14", "infoflow7",
                           setools.IoctlSet([0x4321]), xperm="ioctl")

    def test_std_perm_any(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Xperm rule query match by standard permission."""
        q = TERuleQuery(compiled_policy, ruletype=["neverallow", "neverallowxperm"],
                        perms=set(["ioctl", "hi_w"]), perms_equal=False)

        r = sorted(q.results())
        assert len(r) == 0
        # changed after dropping source policy support
        # assert len(r) == 2
        # util.validate_rule(r[0], TRT.neverallow, "test100", "system", "infoflow2",
        #                   set(["ioctl", "hi_w"]))
        # util.validate_rule(r[1], TRT.neverallowxperm, "test100", "test100", "infoflow2",
        #                   setools.IoctlSet([0x1234]), xperm="ioctl")

    def test_std_perm_equal(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Xperm rule query match by standard permission, equal perm set."""
        q = TERuleQuery(compiled_policy, ruletype=["neverallow", "neverallowxperm"],
                        perms=set(["ioctl", "hi_w"]), perms_equal=True)

        r = sorted(q.results())
        assert len(r) == 0
        # changed after dropping source policy support
        # assert len(r) == 1
        # util.validate_rule(r[0], TRT.neverallow, "test100", "system", "infoflow2",
        #                   set(["ioctl", "hi_w"]))

    def test_xperm_any(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Xperm rule query match any perm set."""
        q = TERuleQuery(compiled_policy, xperms=[(0x9011, 0x9013)], xperms_equal=False)

        r = sorted(q.results())
        assert len(r) == 4
        util.validate_rule(r[0], TRT.allowxperm, "test101a", "test101a", "infoflow7",
                           setools.IoctlSet([0x9011]), xperm="ioctl")
        util.validate_rule(r[1], TRT.allowxperm, "test101b", "test101b", "infoflow7",
                           setools.IoctlSet([0x9011, 0x9012]), xperm="ioctl")
        util.validate_rule(r[2], TRT.allowxperm, "test101c", "test101c", "infoflow7",
                           setools.IoctlSet([0x9011, 0x9012, 0x9013]), xperm="ioctl")
        util.validate_rule(r[3], TRT.allowxperm, "test101d", "test101d", "infoflow7",
                           setools.IoctlSet([0x9011, 0x9012, 0x9013, 0x9014]), xperm="ioctl")

    def test_xperm_equal(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Xperm rule query match equal perm set."""
        q = TERuleQuery(compiled_policy, xperms=[(0x9011, 0x9013)], xperms_equal=True)

        r = sorted(q.results())
        assert len(r) == 1
        util.validate_rule(r[0], TRT.allowxperm, "test101c", "test101c", "infoflow7",
                           setools.IoctlSet([0x9011, 0x9012, 0x9013]), xperm="ioctl")
