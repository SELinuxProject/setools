# Copyright 2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: GPL-2.0-only
#
import pytest
import setools


@pytest.mark.obj_args("tests/library/policyrep/mls.conf")
class TestSensitivity:

    def test_string(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Sensitivity basic string rendering."""
        sens = compiled_policy.lookup_sensitivity("s0")
        assert "s0" == str(sens), f"{sens}"

    def test_statement(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Sensitivity basic statement rendering."""
        sens = compiled_policy.lookup_sensitivity("s2")
        assert "sensitivity s2;" == sens.statement(), sens.statement()

    def test_statement_alias(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Sensitivity one alias statement rendering."""
        sens = compiled_policy.lookup_sensitivity("s0")
        assert "sensitivity s0 alias sname1;" == sens.statement()

    def test_statement_alias2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Sensitivity two alias statement rendering."""
        sens = compiled_policy.lookup_sensitivity("s1")
        assert sens.statement() in ("sensitivity s1 alias { sname2 sname3 };",
                                    "sensitivity s1 alias { sname3 sname2 };"), sens.statement()

    def test_equal(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Sensitivity equal."""
        sens1 = compiled_policy.lookup_sensitivity("s0")
        sens2 = compiled_policy.lookup_sensitivity("s0")
        assert sens1 == sens2

    def test_equal_str(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Sensitivity equal to string."""
        sens = compiled_policy.lookup_sensitivity("s17")
        assert "s17" == sens

    def test_not_equal(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Sensitivity not equal."""
        sens1 = compiled_policy.lookup_sensitivity("s17")
        sens2 = compiled_policy.lookup_sensitivity("s23")
        assert sens1 != sens2

    def test_not_equal_str(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Sensitivity not equal to string."""
        sens = compiled_policy.lookup_sensitivity("s17")
        assert "s0" != sens

    def test_lt(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Sensitivity less-than."""
        # less
        sens1 = compiled_policy.lookup_sensitivity("s17")
        sens2 = compiled_policy.lookup_sensitivity("s23")
        assert sens1 < sens2

        # equal
        sens1 = compiled_policy.lookup_sensitivity("s17")
        sens2 = compiled_policy.lookup_sensitivity("s17")
        assert not (sens1 < sens2)

        # greater
        sens1 = compiled_policy.lookup_sensitivity("s17")
        sens2 = compiled_policy.lookup_sensitivity("s0")
        assert not (sens1 < sens2)

    def test_le(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Sensitivity less-than-or-equal."""
        # less
        sens1 = compiled_policy.lookup_sensitivity("s17")
        sens2 = compiled_policy.lookup_sensitivity("s23")
        assert sens1 <= sens2

        # equal
        sens1 = compiled_policy.lookup_sensitivity("s17")
        sens2 = compiled_policy.lookup_sensitivity("s17")
        assert sens1 <= sens2

        # greater
        sens1 = compiled_policy.lookup_sensitivity("s17")
        sens2 = compiled_policy.lookup_sensitivity("s0")
        assert not (sens1 <= sens2)

    def test_ge(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Sensitivity greater-than-or-equal."""
        # less
        sens1 = compiled_policy.lookup_sensitivity("s17")
        sens2 = compiled_policy.lookup_sensitivity("s23")
        assert not (sens1 >= sens2)

        # equal
        sens1 = compiled_policy.lookup_sensitivity("s17")
        sens2 = compiled_policy.lookup_sensitivity("s17")
        assert sens1 >= sens2

        # greater
        sens1 = compiled_policy.lookup_sensitivity("s17")
        sens2 = compiled_policy.lookup_sensitivity("s0")
        assert sens1 >= sens2

    def test_gt(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Sensitivity greater-than."""
        # less
        sens1 = compiled_policy.lookup_sensitivity("s17")
        sens2 = compiled_policy.lookup_sensitivity("s23")
        assert not (sens1 > sens2)

        # equal
        sens1 = compiled_policy.lookup_sensitivity("s17")
        sens2 = compiled_policy.lookup_sensitivity("s17")
        assert not (sens1 > sens2)

        # greater
        sens1 = compiled_policy.lookup_sensitivity("s17")
        sens2 = compiled_policy.lookup_sensitivity("s0")
        assert sens1 > sens2


@pytest.mark.obj_args("tests/library/policyrep/mls.conf")
class TestCategory:

    def test_string(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Category basic string rendering."""
        cat = compiled_policy.lookup_category("c0")
        assert "c0" == str(cat), f"{cat}"

    def test_statement(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Category basic statement rendering."""
        cat = compiled_policy.lookup_category("c2")
        assert "category c2;" == cat.statement(), cat.statement()


@pytest.mark.obj_args("tests/library/policyrep/mls.conf")
class TestLevel:

    def test_equal(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Level equal."""
        level1 = compiled_policy.lookup_level("s0:c0.c3")
        level2 = compiled_policy.lookup_level("s0:c0.c3")
        assert level1 == level2

    def test_equal_str(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Level equal to string."""
        level = compiled_policy.lookup_level("s2:c0.c3")
        assert "s2:c0.c3" == level, f"{level}"

    def test_not_equal(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Level not equal."""
        level1 = compiled_policy.lookup_level("s0:c0.c3")
        level2 = compiled_policy.lookup_level("s0")
        assert level1 != level2, f"{level1} ||| {level2}"

    def test_not_equal_str(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Level not equal to string."""
        level = compiled_policy.lookup_level("s0:c0.c3")
        assert "s0:c0.c2" != level, f"{level}"

    def test_dom(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Level dominate (ge)."""
        # equal
        level1 = compiled_policy.lookup_level("s1:c0.c3")
        level2 = compiled_policy.lookup_level("s1:c0.c3")
        assert level1 >= level2

        # sens dominate
        level1 = compiled_policy.lookup_level("s2:c0.c3")
        level2 = compiled_policy.lookup_level("s1:c0.c3")
        assert level1 >= level2

        # cat set dominate
        level1 = compiled_policy.lookup_level("s1:c0.c4")
        level2 = compiled_policy.lookup_level("s1:c0.c3")
        assert level1 >= level2

        # sens domby
        level1 = compiled_policy.lookup_level("s0:c0.c3")
        level2 = compiled_policy.lookup_level("s1:c0.c3")
        assert not (level1 >= level2)

        # cat set domby
        level1 = compiled_policy.lookup_level("s1:c0.c2")
        level2 = compiled_policy.lookup_level("s1:c0.c3")
        assert not (level1 >= level2)

        # incomp
        level1 = compiled_policy.lookup_level("s1:c0.c3")
        level2 = compiled_policy.lookup_level("s1:c4.c7")
        assert not (level1 >= level2)

    def test_domby(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Level dominate-by (le)."""
        # equal
        level1 = compiled_policy.lookup_level("s1:c0.c3")
        level2 = compiled_policy.lookup_level("s1:c0.c3")
        assert level1 <= level2

        # sens dominate
        level1 = compiled_policy.lookup_level("s2:c0.c3")
        level2 = compiled_policy.lookup_level("s1:c0.c3")
        assert not (level1 <= level2)

        # cat set dominate
        level1 = compiled_policy.lookup_level("s1:c0.c4")
        level2 = compiled_policy.lookup_level("s1:c0.c3")
        assert not (level1 <= level2)

        # sens domby
        level1 = compiled_policy.lookup_level("s0:c0.c3")
        level2 = compiled_policy.lookup_level("s1:c0.c3")
        assert level1 <= level2

        # cat set domby
        level1 = compiled_policy.lookup_level("s1:c0.c2")
        level2 = compiled_policy.lookup_level("s1:c0.c3")
        assert level1 <= level2

        # incomp
        level1 = compiled_policy.lookup_level("s1:c0.c2")
        level2 = compiled_policy.lookup_level("s1:c7.c9")
        assert not (level1 <= level2)

    def test_proper_dom(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Level proper dominate (gt)."""
        # equal
        level1 = compiled_policy.lookup_level("s1:c0.c3")
        level2 = compiled_policy.lookup_level("s1:c0.c3")
        assert not (level1 > level2)

        # sens dominate
        level1 = compiled_policy.lookup_level("s2:c0.c3")
        level2 = compiled_policy.lookup_level("s1:c0.c3")
        assert level1 > level2

        # cat set dominate
        level1 = compiled_policy.lookup_level("s1:c0.c4")
        level2 = compiled_policy.lookup_level("s1:c0.c3")
        assert level1 > level2

        # sens domby
        level1 = compiled_policy.lookup_level("s0:c0.c3")
        level2 = compiled_policy.lookup_level("s1:c0.c3")
        assert not (level1 > level2)

        # cat set domby
        level1 = compiled_policy.lookup_level("s1:c0.c2")
        level2 = compiled_policy.lookup_level("s1:c0.c3")
        assert not (level1 > level2)

        # incomp
        level1 = compiled_policy.lookup_level("s1:c0.c2")
        level2 = compiled_policy.lookup_level("s1:c7.c9")
        assert not (level1 > level2)

    def test_proper_domby(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Level proper dominate-by (lt)."""
        # equal
        level1 = compiled_policy.lookup_level("s1:c0.c3")
        level2 = compiled_policy.lookup_level("s1:c0.c3")
        assert not (level1 < level2)

        # sens dominate
        level1 = compiled_policy.lookup_level("s2:c0.c3")
        level2 = compiled_policy.lookup_level("s1:c0.c3")
        assert not (level1 < level2)

        # cat set dominate
        level1 = compiled_policy.lookup_level("s1:c0.c4")
        level2 = compiled_policy.lookup_level("s1:c0.c3")
        assert not (level1 < level2)

        # sens domby
        level1 = compiled_policy.lookup_level("s0:c0.c3")
        level2 = compiled_policy.lookup_level("s1:c0.c3")
        assert level1 < level2

        # cat set domby
        level1 = compiled_policy.lookup_level("s1:c0.c2")
        level2 = compiled_policy.lookup_level("s1:c0.c3")
        assert level1 < level2

        # incomp
        level1 = compiled_policy.lookup_level("s1:c0.c2")
        level2 = compiled_policy.lookup_level("s1:c7.c9")
        assert not (level1 < level2)

    def test_incomp(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Level incomparable (xor)."""
        # equal
        level1 = compiled_policy.lookup_level("s1:c0.c3")
        level2 = compiled_policy.lookup_level("s1:c0.c3")
        assert not (level1 ^ level2)

        # sens dominate
        level1 = compiled_policy.lookup_level("s2:c0.c3")
        level2 = compiled_policy.lookup_level("s1:c0.c3")
        assert not (level1 ^ level2)

        # cat set dominate
        level1 = compiled_policy.lookup_level("s1:c0.c4")
        level2 = compiled_policy.lookup_level("s1:c0.c3")
        assert not (level1 ^ level2)

        # sens domby
        level1 = compiled_policy.lookup_level("s0:c0.c3")
        level2 = compiled_policy.lookup_level("s1:c0.c3")
        assert not (level1 ^ level2)

        # cat set domby
        level1 = compiled_policy.lookup_level("s1:c0.c2")
        level2 = compiled_policy.lookup_level("s1:c0.c3")
        assert not (level1 ^ level2)

        # incomp
        level1 = compiled_policy.lookup_level("s1:c0.c2")
        level2 = compiled_policy.lookup_level("s1:c7.c9")
        assert level1 ^ level2

    def test_level_statement(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Level has no statement."""
        level = compiled_policy.lookup_level("s1")
        with pytest.raises(setools.exception.NoStatement):
            level.statement()


@pytest.mark.obj_args("tests/library/policyrep/mls.conf")
class TestRange:

    def test_equal(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Range equality."""
        rangeobj1 = compiled_policy.lookup_range("s0:c0.c2-s2:c0.c5,c7,c9.c11,c13")
        rangeobj2 = compiled_policy.lookup_range("s0:c0.c2-s2:c0.c5,c7,c9.c11,c13")
        assert rangeobj1 == rangeobj2

    def test_equal_string(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Range equal to string."""
        rangeobj = compiled_policy.lookup_range("s0:c0.c2-s2:c0.c5,c7,c9.c11,c13")
        assert "s0:c0.c2-s2:c0.c5,c7,c9.c11,c13" == rangeobj
        assert "s0:c0.c2- s2:c0.c5,c7,c9.c11,c13" == rangeobj
        assert "s0:c0.c2 -s2:c0.c5,c7,c9.c11,c13" == rangeobj
        assert "s0:c0.c2 - s2:c0.c5,c7,c9.c11,c13" == rangeobj

    def test_contains(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Range contains a level."""
        rangeobj = compiled_policy.lookup_range("s0:c1-s2:c0.c10")

        # too low
        level1 = compiled_policy.lookup_level("s0")
        assert not (level1 in rangeobj)

        # low level
        level2 = compiled_policy.lookup_level("s0:c1")
        assert level2 in rangeobj

        # mid
        level3 = compiled_policy.lookup_level("s1:c1,c5")
        assert level3 in rangeobj

        # high level
        level4 = compiled_policy.lookup_level("s2:c0.c10")
        assert level4 in rangeobj

        # too high
        level5 = compiled_policy.lookup_level("s2:c0.c11")
        assert not (level5 in rangeobj)

    def test_range_statement(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Range has no statement."""
        rangeobj = compiled_policy.lookup_range("s0")
        with pytest.raises(setools.exception.NoStatement):
            rangeobj.statement()
