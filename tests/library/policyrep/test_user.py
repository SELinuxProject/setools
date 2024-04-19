# Copyright 2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: GPL-2.0-only
#
import pytest
import setools


@pytest.mark.obj_args("tests/library/policyrep/user_mls.conf")
class TestUserMLS:

    def test_string(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """User basic string rendering."""
        user = compiled_policy.lookup_user("system")
        assert "system" == str(user), f"{user}"

    def test_statement_one_role_mls(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """User statement, one role, MLS."""
        user = compiled_policy.lookup_user("user10")
        assert "user user10 roles system level s1:c2 range s1 - s2:c0.c4;" == \
            user.statement(), user.statement()

    def test_023_statement_two_roles_mls(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """User statement, two roles, MLS."""
        user = compiled_policy.lookup_user("user20")
        # roles are stored in a set, so the role order may vary
        assert user.statement() in (
            "user user20 roles { role20_r role21a_r } level s0 range s0 - s2:c0.c4;",
            "user user20 roles { role21a_r role20_r } level s0 range s0 - s2:c0.c4;"), \
            user.statement()

    def test_roles(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """User roles."""
        user = compiled_policy.lookup_user("user20")
        assert set(['role20_r', 'role21a_r']) == user.roles, user.roles

    def test_level(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """User level."""
        user = compiled_policy.lookup_user("user10")
        assert "s1:c2" == user.mls_level, user.mls_level

    def test_range(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """User level."""
        user = compiled_policy.lookup_user("user20")
        assert "s0 - s2:c0.c4" == user.mls_range, user.mls_range


@pytest.mark.obj_args("tests/library/policyrep/user_standard.conf", mls=False)
class TestUserStandard:

    def test_statement_role(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """User statement, one role."""
        user = compiled_policy.lookup_user("user10")
        assert "user user10 roles system;" == user.statement(), user.statement()

    def test_statement_two_roles(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """User statement, two roles."""
        user = compiled_policy.lookup_user("user20")
        # roles are stored in a set, so the role order may vary
        assert user.statement() in (
            "user user20 roles { role20_r role21a_r };",
            "user user20 roles { role21a_r role20_r };"), \
            user.statement()

    def test_level(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """User level, MLS disabled."""
        user = compiled_policy.lookup_user("user10")
        with pytest.raises(setools.exception.MLSDisabled):
            user.mls_level

    def test_range(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """User level, MLS disabled."""
        user = compiled_policy.lookup_user("user20")
        with pytest.raises(setools.exception.MLSDisabled):
            user.mls_range
