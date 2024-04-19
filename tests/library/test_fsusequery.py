# Copyright 2014, Tresys Technology, LLC
#
# SPDX-License-Identifier: GPL-2.0-only
#
import pytest
import setools


@pytest.mark.obj_args("tests/library/fsusequery.conf")
class TestFSUseQuery:

    def test_unset(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """fs_use_* query with no criteria"""
        # query with no parameters gets all fs_use_*.
        fsu = sorted(compiled_policy.fs_uses())

        q = setools.FSUseQuery(compiled_policy)
        q_fsu = sorted(q.results())

        assert fsu == q_fsu

    def test_fs_exact(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """fs_use_* query with exact fs match"""
        q = setools.FSUseQuery(compiled_policy, fs="test1", fs_regex=False)

        fsu = sorted(s.fs for s in q.results())
        assert ["test1"] == fsu

    def test_fs_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """fs_use_* query with regex fs match"""
        q = setools.FSUseQuery(compiled_policy, fs="test2(a|b)", fs_regex=True)

        fsu = sorted(s.fs for s in q.results())
        assert ["test2a", "test2b"] == fsu

    def test_ruletype(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """fs_use_* query with ruletype match"""
        q = setools.FSUseQuery(compiled_policy, ruletype=['fs_use_trans', 'fs_use_task'])

        fsu = sorted(s.fs for s in q.results())
        assert ["test10a", "test10b"] == fsu

    def test_user_exact(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """fs_use_* query with context user exact match"""
        q = setools.FSUseQuery(compiled_policy, user="user20", user_regex=False)

        fsu = sorted(s.fs for s in q.results())
        assert ["test20"] == fsu

    def test_user_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """fs_use_* query with context user regex match"""
        q = setools.FSUseQuery(compiled_policy, user="user21(a|b)", user_regex=True)

        fsu = sorted(s.fs for s in q.results())
        assert ["test21a", "test21b"] == fsu

    def test_role_exact(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """fs_use_* query with context role exact match"""
        q = setools.FSUseQuery(compiled_policy, role="role30_r", role_regex=False)

        fsu = sorted(s.fs for s in q.results())
        assert ["test30"] == fsu

    def test_role_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """fs_use_* query with context role regex match"""
        q = setools.FSUseQuery(compiled_policy, role="role31(a|c)_r", role_regex=True)

        fsu = sorted(s.fs for s in q.results())
        assert ["test31a", "test31c"] == fsu

    def test_type_exact(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """fs_use_* query with context type exact match"""
        q = setools.FSUseQuery(compiled_policy, type_="type40", type_regex=False)

        fsu = sorted(s.fs for s in q.results())
        assert ["test40"] == fsu

    def test_type_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """fs_use_* query with context type regex match"""
        q = setools.FSUseQuery(compiled_policy, type_="type41(b|c)", type_regex=True)

        fsu = sorted(s.fs for s in q.results())
        assert ["test41b", "test41c"] == fsu

    def test_range_exact(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """fs_use_* query with context range exact match"""
        q = setools.FSUseQuery(compiled_policy, range_="s0:c1 - s0:c0.c4")

        fsu = sorted(s.fs for s in q.results())
        assert ["test50"] == fsu

    def test_range_overlap1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """fs_use_* query with context range overlap match (equal)"""
        q = setools.FSUseQuery(compiled_policy, range_="s1:c1 - s1:c0.c4", range_overlap=True)

        fsu = sorted(s.fs for s in q.results())
        assert ["test51"] == fsu

    def test_range_overlap2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """fs_use_* query with context range overlap match (subset)"""
        q = setools.FSUseQuery(compiled_policy, range_="s1:c1,c2 - s1:c0.c3", range_overlap=True)

        fsu = sorted(s.fs for s in q.results())
        assert ["test51"] == fsu

    def test_range_overlap3(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """fs_use_* query with context range overlap match (superset)"""
        q = setools.FSUseQuery(compiled_policy, range_="s1 - s1:c0.c4", range_overlap=True)

        fsu = sorted(s.fs for s in q.results())
        assert ["test51"] == fsu

    def test_range_overlap4(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """fs_use_* query with context range overlap match (overlap low level)"""
        q = setools.FSUseQuery(compiled_policy, range_="s1 - s1:c1,c2", range_overlap=True)

        fsu = sorted(s.fs for s in q.results())
        assert ["test51"] == fsu

    def test_range_overlap5(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """fs_use_* query with context range overlap match (overlap high level)"""
        q = setools.FSUseQuery(compiled_policy, range_="s1:c1,c2 - s1:c0.c4", range_overlap=True)

        fsu = sorted(s.fs for s in q.results())
        assert ["test51"] == fsu

    def test_range_subset1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """fs_use_* query with context range subset match"""
        q = setools.FSUseQuery(compiled_policy, range_="s2:c1,c2 - s2:c0.c3", range_overlap=True)

        fsu = sorted(s.fs for s in q.results())
        assert ["test52"] == fsu

    def test_range_subset2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """fs_use_* query with context range subset match (equal)"""
        q = setools.FSUseQuery(compiled_policy, range_="s2:c1 - s2:c1.c3", range_overlap=True)

        fsu = sorted(s.fs for s in q.results())
        assert ["test52"] == fsu

    def test_range_superset1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """fs_use_* query with context range superset match"""
        q = setools.FSUseQuery(compiled_policy, range_="s3 - s3:c0.c4", range_superset=True)

        fsu = sorted(s.fs for s in q.results())
        assert ["test53"] == fsu

    def test_range_superset2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """fs_use_* query with context range superset match (equal)"""
        q = setools.FSUseQuery(compiled_policy, range_="s3:c1 - s3:c1.c3", range_superset=True)

        fsu = sorted(s.fs for s in q.results())
        assert ["test53"] == fsu

    def test_range_proper_subset1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """fs_use_* query with context range proper subset match"""
        q = setools.FSUseQuery(compiled_policy, range_="s4:c1,c2", range_subset=True,
                               range_proper=True)

        fsu = sorted(s.fs for s in q.results())
        assert ["test54"] == fsu

    def test_range_proper_subset2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """fs_use_* query with context range proper subset match (equal)"""
        q = setools.FSUseQuery(compiled_policy, range_="s4:c1 - s4:c1.c3", range_subset=True,
                               range_proper=True)

        fsu = sorted(s.fs for s in q.results())
        assert [] == fsu

    def test_range_proper_subset3(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """fs_use_* query with context range proper subset match (equal low only)"""
        q = setools.FSUseQuery(compiled_policy, range_="s4:c1 - s4:c1.c2", range_subset=True,
                               range_proper=True)

        fsu = sorted(s.fs for s in q.results())
        assert ["test54"] == fsu

    def test_range_proper_subset4(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """fs_use_* query with context range proper subset match (equal high only)"""
        q = setools.FSUseQuery(compiled_policy, range_="s4:c1,c2 - s4:c1.c3", range_subset=True,
                               range_proper=True)

        fsu = sorted(s.fs for s in q.results())
        assert ["test54"] == fsu

    def test_range_proper_superset1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """fs_use_* query with context range proper superset match"""
        q = setools.FSUseQuery(compiled_policy, range_="s5 - s5:c0.c4", range_superset=True,
                               range_proper=True)

        fsu = sorted(s.fs for s in q.results())
        assert ["test55"] == fsu

    def test_range_proper_superset2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """fs_use_* query with context range proper superset match (equal)"""
        q = setools.FSUseQuery(compiled_policy, range_="s5:c1 - s5:c1.c3", range_superset=True,
                               range_proper=True)

        fsu = sorted(s.fs for s in q.results())
        assert [] == fsu

    def test_range_proper_superset3(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """fs_use_* query with context range proper superset match (equal low)"""
        q = setools.FSUseQuery(compiled_policy, range_="s5:c1 - s5:c1.c4", range_superset=True,
                               range_proper=True)

        fsu = sorted(s.fs for s in q.results())
        assert ["test55"] == fsu

    def test_range_proper_superset4(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """fs_use_* query with context range proper superset match (equal high)"""
        q = setools.FSUseQuery(compiled_policy, range_="s5 - s5:c1.c3", range_superset=True,
                               range_proper=True)

        fsu = sorted(s.fs for s in q.results())
        assert ["test55"] == fsu
