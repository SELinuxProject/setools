# Copyright 2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: GPL-2.0-only
#
import pytest
import setools


@pytest.mark.obj_args("tests/library/sensitivityquery.conf")
class TestSensitivityQuery:

    def test_unset(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Sensitivity query with no criteria."""
        # query with no parameters gets all sensitivities.
        allsens = sorted(str(c) for c in compiled_policy.sensitivities())

        q = setools.SensitivityQuery(compiled_policy)
        qsens = sorted(str(c) for c in q.results())

        assert allsens == qsens

    def test_name_exact(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Sensitivity query with exact name match."""
        q = setools.SensitivityQuery(compiled_policy, name="test1")

        sens = sorted(str(c) for c in q.results())
        assert ["test1"] == sens

    def test_name_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Sensitivity query with regex name match."""
        q = setools.SensitivityQuery(compiled_policy, name="test2(a|b)", name_regex=True)

        sens = sorted(str(c) for c in q.results())
        assert ["test2a", "test2b"] == sens

    def test_alias_exact(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Sensitivity query with exact alias match."""
        q = setools.SensitivityQuery(compiled_policy, alias="test10a")

        sens = sorted(str(t) for t in q.results())
        assert ["test10s1"] == sens

    def test_alias_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Sensitivity query with regex alias match."""
        q = setools.SensitivityQuery(compiled_policy, alias="test11(a|b)", alias_regex=True)

        sens = sorted(str(t) for t in q.results())
        assert ["test11s1", "test11s2"] == sens

    def test_sens_equal(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Sensitivity query with sens equality."""
        q = setools.SensitivityQuery(compiled_policy, sens="test20")

        sens = sorted(str(u) for u in q.results())
        assert ["test20"] == sens

    def test_sens_dom1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Sensitivity query with sens dominance."""
        q = setools.SensitivityQuery(compiled_policy, sens="test21crit", sens_dom=True)

        sens = sorted(str(u) for u in q.results())
        assert ["test21", "test21crit"] == sens

    def test_sens_dom2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Sensitivity query with sens dominance (equal)."""
        q = setools.SensitivityQuery(compiled_policy, sens="test21", sens_dom=True)

        sens = sorted(str(u) for u in q.results())
        assert ["test21"] == sens

    def test_sens_domby1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Sensitivity query with sens dominated-by."""
        q = setools.SensitivityQuery(compiled_policy, sens="test22crit", sens_domby=True)

        sens = sorted(str(u) for u in q.results())
        assert ["test22", "test22crit"] == sens

    def test_sens_domby2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Sensitivity query with sens dominated-by (equal)."""
        q = setools.SensitivityQuery(compiled_policy, sens="test22", sens_domby=True)

        sens = sorted(str(u) for u in q.results())
        assert ["test22"] == sens
