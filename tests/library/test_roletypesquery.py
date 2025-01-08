# Copyright 2025, Christian Göttsche
#
# SPDX-License-Identifier: GPL-2.0-only
#
import pytest
import setools


@pytest.mark.obj_args("tests/library/roletypesquery.conf")
class TestRoleTypesQuery:

    def test_name_nomatch(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Type with no associated role."""
        q = setools.RoleTypesQuery(compiled_policy, name="test1")

        roles = sorted(str(r) for r in q.results())
        assert [] == roles

    def test_name_onematch(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Type with one associated role."""
        q = setools.RoleTypesQuery(compiled_policy, name="test2a")

        roles = sorted(str(r) for r in q.results())
        assert ["test2ra"] == roles

    def test_name_multiplematches(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Type with multiple associated roles."""
        q = setools.RoleTypesQuery(compiled_policy, name="test3a")

        roles = sorted(str(r) for r in q.results())
        assert ["test3rb", "test3rc", "test3rd"] == roles

    def test_name_multiplematches_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Multiple types with multiple associated roles."""
        q = setools.RoleTypesQuery(compiled_policy, name="test3", name_regex=True)

        roles = sorted(str(r) for r in q.results())
        assert ["test3ra", "test3rb", "test3rc", "test3rd"] == roles
