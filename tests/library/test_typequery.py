# Copyright 2014-2015, Tresys Technology, LLC
# Copyright 2019, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: GPL-2.0-only
#
import pytest
import setools


@pytest.mark.obj_args("tests/library/typequery.conf")
class TestTypeQuery:

    def test_unset(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Type query with no criteria."""
        # query with no parameters gets all types.
        alltypes = sorted(compiled_policy.types())

        q = setools.TypeQuery(compiled_policy)
        qtypes = sorted(q.results())

        assert alltypes == qtypes

    def test_name_exact(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Type query with exact name match."""
        q = setools.TypeQuery(compiled_policy, name="test1")

        types = sorted(str(t) for t in q.results())
        assert ["test1"] == types

    def test_name_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Type query with regex name match."""
        q = setools.TypeQuery(compiled_policy, name="test2(a|b)", name_regex=True)

        types = sorted(str(t) for t in q.results())
        assert ["test2a", "test2b"] == types

    def test_attr_intersect(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Type query with attribute set intersection."""
        q = setools.TypeQuery(compiled_policy, attrs=["test10a", "test10b"])

        types = sorted(str(t) for t in q.results())
        assert ["test10t1", "test10t2", "test10t3",
                "test10t4", "test10t5", "test10t6"] == types

    def test_attr_equality(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Type query with attribute set equality."""
        q = setools.TypeQuery(compiled_policy, attrs=["test11a", "test11b"], attrs_equal=True)

        types = sorted(str(t) for t in q.results())
        assert ["test11t2"] == types

    def test_attr_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Type query with attribute regex match."""
        q = setools.TypeQuery(compiled_policy, attrs="test12(a|b)", attrs_regex=True)

        types = sorted(str(t) for t in q.results())
        assert ["test12t1", "test12t2", "test12t3",
                "test12t4", "test12t5", "test12t6"] == types

    def test_alias_exact(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Type query with exact alias match."""
        q = setools.TypeQuery(compiled_policy, alias="test20a")

        types = sorted(str(t) for t in q.results())
        assert ["test20t1"] == types

    def test_alias_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Type query with regex alias match."""
        q = setools.TypeQuery(compiled_policy, alias="test21(a|b)", alias_regex=True)

        types = sorted(str(t) for t in q.results())
        assert ["test21t1", "test21t2"] == types

    def test_alias_dereference(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Type query with alias dereference."""
        q = setools.TypeQuery(compiled_policy, name="test22alias", alias_deref=True)

        types = sorted(str(t) for t in q.results())
        assert ["test22"] == types

    def test_permissive(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Type query with permissive match"""
        q = setools.TypeQuery(compiled_policy, permissive=True)

        types = sorted(str(t) for t in q.results())
        assert ["test30"] == types
