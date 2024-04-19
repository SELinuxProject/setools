# Copyright 2014, Tresys Technology, LLC
#
# SPDX-License-Identifier: GPL-2.0-only
#
import pytest
import setools


@pytest.mark.obj_args("tests/library/commonquery.conf")
class TestCommonQuery:

    def test_unset(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Common query with no criteria."""
        # query with no parameters gets all types.
        commons = sorted(compiled_policy.commons())

        q = setools.CommonQuery(compiled_policy)
        q_commons = sorted(q.results())

        assert commons == q_commons

    def test_name_exact(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Common query with exact name match."""
        q = setools.CommonQuery(compiled_policy, name="test1")

        commons = sorted(str(c) for c in q.results())
        assert ["test1"] == commons

    def test_name_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Common query with regex name match."""
        q = setools.CommonQuery(compiled_policy, name="test2(a|b)", name_regex=True)

        commons = sorted(str(c) for c in q.results())
        assert ["test2a", "test2b"] == commons

    def test_perm_indirect_intersect(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Common query with intersect permission name patch."""
        q = setools.CommonQuery(compiled_policy, perms=set(["null"]), perms_equal=False)

        commons = sorted(str(c) for c in q.results())
        assert ["test10a", "test10b"] == commons

    def test_perm_indirect_equal(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Common query with equal permission name patch."""
        q = setools.CommonQuery(compiled_policy, perms=set(["read", "write"]), perms_equal=True)

        commons = sorted(str(c) for c in q.results())
        assert ["test11a"] == commons

    def test_perm_indirect_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Common query with regex permission name patch."""
        q = setools.CommonQuery(compiled_policy, perms="sig.+", perms_regex=True)

        commons = sorted(str(c) for c in q.results())
        assert ["test12a", "test12b"] == commons
