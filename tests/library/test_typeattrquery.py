# Copyright 2014-2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: GPL-2.0-only
#
import pytest
import setools


@pytest.mark.obj_args("tests/library/typeattrquery.conf")
class TestTypeAttributeQuery:

    def test_unset(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Type attribute query with no criteria."""
        # query with no parameters gets all attrs.
        allattrs = sorted(compiled_policy.typeattributes())

        q = setools.TypeAttributeQuery(compiled_policy)
        qattrs = sorted(q.results())

        assert allattrs == qattrs

    def test_name_exact(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Type attribute query with exact name match."""
        q = setools.TypeAttributeQuery(compiled_policy, name="test1")

        attrs = sorted(str(t) for t in q.results())
        assert ["test1"] == attrs

    def test_name_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Type attribute query with regex name match."""
        q = setools.TypeAttributeQuery(compiled_policy, name="test2(a|b)", name_regex=True)

        attrs = sorted(str(t) for t in q.results())
        assert ["test2a", "test2b"] == attrs

    def test_type_set_intersect(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Type attribute query with type set intersection."""
        q = setools.TypeAttributeQuery(compiled_policy, types=["test10t1", "test10t7"])

        attrs = sorted(str(t) for t in q.results())
        assert ["test10a", "test10c"] == attrs

    def test_type_set_equality(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Type attribute query with type set equality."""
        q = setools.TypeAttributeQuery(compiled_policy, types=["test11t1", "test11t2",
                                       "test11t3", "test11t5"], types_equal=True)

        attrs = sorted(str(t) for t in q.results())
        assert ["test11a"] == attrs

    def test_type_set_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Type attribute query with type set regex match."""
        q = setools.TypeAttributeQuery(compiled_policy, types="test12t(1|2)", types_regex=True)

        attrs = sorted(str(t) for t in q.results())
        assert ["test12a", "test12b"] == attrs
