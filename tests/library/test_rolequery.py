# Copyright 2014, Tresys Technology, LLC
#
# SPDX-License-Identifier: GPL-2.0-only
#
import pytest
import setools


@pytest.mark.obj_args("tests/library/rolequery.conf")
class TestRoleQuery:

    def test_unset(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Role query with no criteria."""
        # query with no parameters gets all types.
        roles = sorted(compiled_policy.roles())

        q = setools.RoleQuery(compiled_policy)
        q_roles = sorted(q.results())

        assert roles == q_roles

    def test_name_exact(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Role query with exact name match."""
        q = setools.RoleQuery(compiled_policy, name="test1")

        roles = sorted(str(r) for r in q.results())
        assert ["test1"] == roles

    def test_name_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Role query with regex name match."""
        q = setools.RoleQuery(compiled_policy, name="test2(a|b)", name_regex=True)

        roles = sorted(str(r) for r in q.results())
        assert ["test2a", "test2b"] == roles

    def test_type_intersect(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Role query with type set intersection."""
        q = setools.RoleQuery(compiled_policy, types=["test10a", "test10b"])

        roles = sorted(str(r) for r in q.results())
        assert ["test10r1", "test10r2", "test10r3",
                "test10r4", "test10r5", "test10r6"] == roles

    def test_type_equality(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Role query with type set equality."""
        q = setools.RoleQuery(compiled_policy, types=["test11a", "test11b"], types_equal=True)

        roles = sorted(str(r) for r in q.results())
        assert ["test11r2"] == roles

    def test_type_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Role query with type set match."""
        q = setools.RoleQuery(compiled_policy, types="test12(a|b)", types_regex=True)

        roles = sorted(str(r) for r in q.results())
        assert ["test12r1", "test12r2", "test12r3",
                "test12r4", "test12r5", "test12r6"] == roles
