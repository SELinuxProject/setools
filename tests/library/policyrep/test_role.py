# Copyright 2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: GPL-2.0-only
#
import pytest
import setools


@pytest.mark.obj_args("tests/library/policyrep/role.conf")
class TestRole:

    def test_string(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Role basic string rendering."""
        role = compiled_policy.lookup_role("role20_r")
        assert "role20_r" == str(role), f"{role}"

    def test_statement_type(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Role statement, one type."""
        role = compiled_policy.lookup_role("role20_r")
        assert "role role20_r types system;" == role.statement(), role.statement()

    def test_statement_two_types(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Role statement, two types."""
        role = compiled_policy.lookup_role("rolename21")
        assert "role rolename21 types { type31a type31b };" == role.statement(), role.statement()

    def test_statement_decl(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Role statement, no types."""
        # This is an unlikely corner case, where a role
        # has been declared but has no types.
        role = compiled_policy.lookup_role("rolename22")
        assert "role rolename22;" == role.statement(), role.statement()

    def test_types(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Role types generator."""
        role = compiled_policy.lookup_role("rolename23")
        types = sorted(role.types())
        assert ["type31b", "type31c"] == types, types

    def test_expand(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Role expansion"""
        role = compiled_policy.lookup_role("system")
        expanded = list(role.expand())
        assert 1 == len(expanded), expanded
        assert role == expanded[0], expanded
