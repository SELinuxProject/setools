# Copyright 2014-2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: GPL-2.0-only
#
import pytest
import setools


@pytest.mark.obj_args("tests/library/userquery.conf")
class TestUserQuery:

    def test_unset(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """User query with no criteria."""
        # query with no parameters gets all types.
        allusers = sorted(compiled_policy.users())

        q = setools.UserQuery(compiled_policy)
        qusers = sorted(q.results())

        assert allusers == qusers

    def test_name_exact(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """User query with exact name match."""
        q = setools.UserQuery(compiled_policy, name="test1_u")

        users = sorted(str(u) for u in q.results())
        assert ["test1_u"] == users

    def test_name_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """User query with regex name match."""
        q = setools.UserQuery(compiled_policy, name="test2_u(1|2)", name_regex=True)

        users = sorted(str(u) for u in q.results())
        assert ["test2_u1", "test2_u2"] == users

    def test_role_intersect(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """User query with role set intersection."""
        q = setools.UserQuery(compiled_policy, roles=["test10a_r", "test10b_r"])

        users = sorted(str(u) for u in q.results())
        assert ["test10_u1", "test10_u2", "test10_u3",
                "test10_u4", "test10_u5", "test10_u6"] == users

    def test_role_equality(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """User query with role set equality."""
        q = setools.UserQuery(
            compiled_policy, roles=["test11a_r", "test11b_r"], roles_equal=True)

        users = sorted(str(u) for u in q.results())
        assert ["test11_u2"] == users

    def test_role_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """User query with role regex match."""
        q = setools.UserQuery(compiled_policy, roles="test12(a|b)_r", roles_regex=True)

        users = sorted(str(u) for u in q.results())
        assert ["test12_u1", "test12_u2", "test12_u3",
                "test12_u4", "test12_u5", "test12_u6"] == users

    def test_level_equal(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """User query with default level equality."""
        q = setools.UserQuery(compiled_policy, level="s3:c0,c4")

        users = sorted(str(u) for u in q.results())
        assert ["test20"] == users

    def test_level_dom1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """User query with default level dominance."""
        q = setools.UserQuery(compiled_policy, level="s2:c1,c2,c4", level_dom=True)

        users = sorted(str(u) for u in q.results())
        assert ["test21"] == users

    def test_level_dom2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """User query with default level dominance (equal)."""
        q = setools.UserQuery(compiled_policy, level="s2:c1,c4", level_dom=True)

        users = sorted(str(u) for u in q.results())
        assert ["test21"] == users

    def test_level_domby1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """User query with default level dominated-by."""
        q = setools.UserQuery(compiled_policy, level="s3:c2", level_domby=True)

        users = sorted(str(u) for u in q.results())
        assert ["test22"] == users

    def test_level_domby2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """User query with default level dominated-by (equal)."""
        q = setools.UserQuery(compiled_policy, level="s3:c2,c4", level_domby=True)

        users = sorted(str(u) for u in q.results())
        assert ["test22"] == users

    def test_level_incomp(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """User query with default level icomparable."""
        q = setools.UserQuery(compiled_policy, level="s5:c0.c5,c7", level_incomp=True)

        users = sorted(str(u) for u in q.results())
        assert ["test23"] == users

    def test_range_exact(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """User query with  range exact match"""
        q = setools.UserQuery(compiled_policy, range_="s0:c5 - s0:c0.c5")

        users = sorted(str(u) for u in q.results())
        assert ["test40"] == users

    def test_range_overlap1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """User query with range overlap match (equal)"""
        q = setools.UserQuery(compiled_policy, range_="s1:c5 - s1:c1.c3,c5", range_overlap=True)

        users = sorted(str(u) for u in q.results())
        assert ["test41"] == users

    def test_range_overlap2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """User query with range overlap match (subset)"""
        q = setools.UserQuery(compiled_policy, range_="s1:c2,c5 - s1:c2.c3,c5", range_overlap=True)

        users = sorted(str(u) for u in q.results())
        assert ["test41"] == users

    def test_range_overlap3(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """User query with range overlap match (superset)"""
        q = setools.UserQuery(compiled_policy, range_="s1 - s1:c0.c5", range_overlap=True)

        users = sorted(str(u) for u in q.results())
        assert ["test41"] == users

    def test_range_overlap4(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """User query with range overlap match (overlap low level)"""
        q = setools.UserQuery(compiled_policy, range_="s1:c5 - s1:c2,c5", range_overlap=True)

        users = sorted(str(u) for u in q.results())
        assert ["test41"] == users

    def test_range_overlap5(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """User query with range overlap match (overlap high level)"""
        q = setools.UserQuery(compiled_policy, range_="s1:c5,c2 - s1:c1.c3,c5", range_overlap=True)

        users = sorted(str(u) for u in q.results())
        assert ["test41"] == users

    def test_range_subset1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """User query with range subset match"""
        q = setools.UserQuery(compiled_policy, range_="s2:c2,c5 - s2:c2.c3,c5", range_overlap=True)

        users = sorted(str(u) for u in q.results())
        assert ["test42"] == users

    def test_range_subset2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """User query with range subset match (equal)"""
        q = setools.UserQuery(compiled_policy, range_="s2:c5 - s2:c1.c3,c5", range_overlap=True)

        users = sorted(str(u) for u in q.results())
        assert ["test42"] == users

    def test_range_superset1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """User query with range superset match"""
        q = setools.UserQuery(compiled_policy, range_="s3 - s3:c0.c6", range_superset=True)

        users = sorted(str(u) for u in q.results())
        assert ["test43"] == users

    def test_range_superset2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """User query with range superset match (equal)"""
        q = setools.UserQuery(compiled_policy, range_="s3:c5 - s3:c1.c3,c5.c6",
                              range_superset=True)

        users = sorted(str(u) for u in q.results())
        assert ["test43"] == users

    def test_range_proper_subset1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """User query with range proper subset match"""
        q = setools.UserQuery(compiled_policy, range_="s4:c2,c5", range_subset=True,
                              range_proper=True)

        users = sorted(str(u) for u in q.results())
        assert ["test44"] == users

    def test_range_proper_subset2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """User query with range proper subset match (equal)"""
        q = setools.UserQuery(compiled_policy, range_="s4:c5 - s4:c1.c3,c5", range_subset=True,
                              range_proper=True)

        users = sorted(str(u) for u in q.results())
        assert [] == users

    def test_range_proper_subset3(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """User query with range proper subset match (equal low)"""
        q = setools.UserQuery(compiled_policy, range_="s4:c5 - s4:c1.c2,c5", range_subset=True,
                              range_proper=True)

        users = sorted(str(u) for u in q.results())
        assert ["test44"] == users

    def test_range_proper_subset4(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """User query with range proper subset match (equal high)"""
        q = setools.UserQuery(compiled_policy, range_="s4:c1,c5 - s4:c1.c3,c5", range_subset=True,
                              range_proper=True)

        users = sorted(str(u) for u in q.results())
        assert ["test44"] == users

    def test_range_proper_superset1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """User query with range proper superset match"""
        q = setools.UserQuery(compiled_policy, range_="s5 - s5:c0.c5", range_superset=True,
                              range_proper=True)

        users = sorted(str(u) for u in q.results())
        assert ["test45"] == users

    def test_range_proper_superset2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """User query with range proper superset match (equal)"""
        q = setools.UserQuery(compiled_policy, range_="s5:c5 - s5:c1.c3,c5", range_superset=True,
                              range_proper=True)

        users = sorted(str(u) for u in q.results())
        assert [] == users

    def test_range_proper_superset3(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """User query with range proper superset match (equal low)"""
        q = setools.UserQuery(compiled_policy, range_="s5:c5 - s5:c1.c5", range_superset=True,
                              range_proper=True)

        users = sorted(str(u) for u in q.results())
        assert ["test45"] == users

    def test_range_proper_superset4(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """User query with range proper superset match (equal high)"""
        q = setools.UserQuery(compiled_policy, range_="s5 - s5:c1.c3,c5", range_superset=True,
                              range_proper=True)

        users = sorted(str(u) for u in q.results())
        assert ["test45"] == users
