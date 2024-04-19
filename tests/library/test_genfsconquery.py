# Copyright 2014, Tresys Technology, LLC
#
# SPDX-License-Identifier: GPL-2.0-only
#
import stat

import pytest
import setools


@pytest.mark.obj_args("tests/library/genfsconquery.conf")
class TestGenfsconQuery:

    def test_unset(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Genfscon query with no criteria"""
        # query with no parameters gets all genfs.
        genfs = sorted(compiled_policy.genfscons())

        q = setools.GenfsconQuery(compiled_policy)
        q_genfs = sorted(q.results())

        assert genfs == q_genfs

    def test_fs_exact(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Genfscon query with exact fs match"""
        q = setools.GenfsconQuery(compiled_policy, fs="test1", fs_regex=False)

        genfs = sorted(s.fs for s in q.results())
        assert ["test1"] == genfs

    def test_fs_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Genfscon query with regex fs match"""
        q = setools.GenfsconQuery(compiled_policy, fs="test2(a|b)", fs_regex=True)

        genfs = sorted(s.fs for s in q.results())
        assert ["test2a", "test2b"] == genfs

    def test_path_exact(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Genfscon query with exact path match"""
        q = setools.GenfsconQuery(compiled_policy, path="/sys", path_regex=False)

        genfs = sorted(s.fs for s in q.results())
        assert ["test10"] == genfs

    def test_path_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Genfscon query with regex path match"""
        q = setools.GenfsconQuery(compiled_policy, path="/(spam|eggs)", path_regex=True)

        genfs = sorted(s.fs for s in q.results())
        assert ["test11a", "test11b"] == genfs

    def test_user_exact(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Genfscon query with context user exact match"""
        q = setools.GenfsconQuery(compiled_policy, user="user20", user_regex=False)

        genfs = sorted(s.fs for s in q.results())
        assert ["test20"] == genfs

    def test_user_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Genfscon query with context user regex match"""
        q = setools.GenfsconQuery(compiled_policy, user="user21(a|b)", user_regex=True)

        genfs = sorted(s.fs for s in q.results())
        assert ["test21a", "test21b"] == genfs

    def test_role_exact(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Genfscon query with context role exact match"""
        q = setools.GenfsconQuery(compiled_policy, role="role30_r", role_regex=False)

        genfs = sorted(s.fs for s in q.results())
        assert ["test30"] == genfs

    def test_role_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Genfscon query with context role regex match"""
        q = setools.GenfsconQuery(compiled_policy, role="role31(a|c)_r", role_regex=True)

        genfs = sorted(s.fs for s in q.results())
        assert ["test31a", "test31c"] == genfs

    def test_type_exact(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Genfscon query with context type exact match"""
        q = setools.GenfsconQuery(compiled_policy, type_="type40", type_regex=False)

        genfs = sorted(s.fs for s in q.results())
        assert ["test40"] == genfs

    def test_type_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Genfscon query with context type regex match"""
        q = setools.GenfsconQuery(compiled_policy, type_="type41(b|c)", type_regex=True)

        genfs = sorted(s.fs for s in q.results())
        assert ["test41b", "test41c"] == genfs

    def test_file_type(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Genfscon query with file type match"""
        q = setools.GenfsconQuery(compiled_policy, filetype=stat.S_IFBLK)

        genfs = sorted(s.fs for s in q.results())
        assert ["test50b"] == genfs

    def test_range_exact(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Genfscon query with context range exact match"""
        q = setools.GenfsconQuery(compiled_policy, range_="s0:c1 - s0:c0.c4")

        genfs = sorted(s.fs for s in q.results())
        assert ["test60"] == genfs

    def test_range_overlap1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Genfscon query with context range overlap match (equal)"""
        q = setools.GenfsconQuery(compiled_policy, range_="s1:c1 - s1:c0.c4", range_overlap=True)

        genfs = sorted(s.fs for s in q.results())
        assert ["test61"] == genfs

    def test_range_overlap2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Genfscon query with context range overlap match (subset)"""
        q = setools.GenfsconQuery(compiled_policy, range_="s1:c1,c2 - s1:c0.c3",
                                  range_overlap=True)

        genfs = sorted(s.fs for s in q.results())
        assert ["test61"] == genfs

    def test_range_overlap3(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Genfscon query with context range overlap match (superset)"""
        q = setools.GenfsconQuery(compiled_policy, range_="s1 - s1:c0.c4", range_overlap=True)

        genfs = sorted(s.fs for s in q.results())
        assert ["test61"] == genfs

    def test_range_overlap4(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Genfscon query with context range overlap match (overlap low level)"""
        q = setools.GenfsconQuery(compiled_policy, range_="s1 - s1:c1,c2", range_overlap=True)

        genfs = sorted(s.fs for s in q.results())
        assert ["test61"] == genfs

    def test_range_overlap5(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Genfscon query with context range overlap match (overlap high level)"""
        q = setools.GenfsconQuery(compiled_policy, range_="s1:c1,c2 - s1:c0.c4",
                                  range_overlap=True)

        genfs = sorted(s.fs for s in q.results())
        assert ["test61"] == genfs

    def test_range_subset1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Genfscon query with context range subset match"""
        q = setools.GenfsconQuery(compiled_policy, range_="s2:c1,c2 - s2:c0.c3",
                                  range_overlap=True)

        genfs = sorted(s.fs for s in q.results())
        assert ["test62"] == genfs

    def test_range_subset2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Genfscon query with context range subset match (equal)"""
        q = setools.GenfsconQuery(compiled_policy, range_="s2:c1 - s2:c1.c3", range_overlap=True)

        genfs = sorted(s.fs for s in q.results())
        assert ["test62"] == genfs

    def test_range_superset1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Genfscon query with context range superset match"""
        q = setools.GenfsconQuery(compiled_policy, range_="s3 - s3:c0.c4", range_superset=True)

        genfs = sorted(s.fs for s in q.results())
        assert ["test63"] == genfs

    def test_range_superset2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Genfscon query with context range superset match (equal)"""
        q = setools.GenfsconQuery(compiled_policy, range_="s3:c1 - s3:c1.c3", range_superset=True)

        genfs = sorted(s.fs for s in q.results())
        assert ["test63"] == genfs

    def test_range_proper_subset1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Genfscon query with context range proper subset match"""
        q = setools.GenfsconQuery(compiled_policy, range_="s4:c1,c2", range_subset=True,
                                  range_proper=True)

        genfs = sorted(s.fs for s in q.results())
        assert ["test64"] == genfs

    def test_range_proper_subset2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Genfscon query with context range proper subset match (equal)"""
        q = setools.GenfsconQuery(compiled_policy, range_="s4:c1 - s4:c1.c3", range_subset=True,
                                  range_proper=True)

        genfs = sorted(s.fs for s in q.results())
        assert [] == genfs

    def test_range_proper_subset3(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Genfscon query with context range proper subset match (equal low only)"""
        q = setools.GenfsconQuery(compiled_policy, range_="s4:c1 - s4:c1.c2", range_subset=True,
                                  range_proper=True)

        genfs = sorted(s.fs for s in q.results())
        assert ["test64"] == genfs

    def test_range_proper_subset4(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Genfscon query with context range proper subset match (equal high only)"""
        q = setools.GenfsconQuery(compiled_policy, range_="s4:c1,c2 - s4:c1.c3", range_subset=True,
                                  range_proper=True)

        genfs = sorted(s.fs for s in q.results())
        assert ["test64"] == genfs

    def test_range_proper_superset1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Genfscon query with context range proper superset match"""
        q = setools.GenfsconQuery(compiled_policy, range_="s5 - s5:c0.c4", range_superset=True,
                                  range_proper=True)

        genfs = sorted(s.fs for s in q.results())
        assert ["test65"] == genfs

    def test_range_proper_superset2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Genfscon query with context range proper superset match (equal)"""
        q = setools.GenfsconQuery(compiled_policy, range_="s5:c1 - s5:c1.c3", range_superset=True,
                                  range_proper=True)

        genfs = sorted(s.fs for s in q.results())
        assert [] == genfs

    def test_range_proper_superset3(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Genfscon query with context range proper superset match (equal low)"""
        q = setools.GenfsconQuery(compiled_policy, range_="s5:c1 - s5:c1.c4", range_superset=True,
                                  range_proper=True)

        genfs = sorted(s.fs for s in q.results())
        assert ["test65"] == genfs

    def test_range_proper_superset4(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Genfscon query with context range proper superset match (equal high)"""
        q = setools.GenfsconQuery(compiled_policy, range_="s5 - s5:c1.c3", range_superset=True,
                                  range_proper=True)

        genfs = sorted(s.fs for s in q.results())
        assert ["test65"] == genfs
