# Copyright 2018, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: GPL-2.0-only
#
import pytest
import setools


@pytest.mark.obj_args("tests/library/ibendportconquery.conf")
class TestIbendportconQuery:

    def test_unset(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Ibendportcon query with no criteria"""
        # query with no parameters gets all ibendportcons.
        ibendportcons = sorted(compiled_policy.ibendportcons())

        q = setools.IbendportconQuery(compiled_policy)
        q_ibendportcons = sorted(q.results())

        assert ibendportcons == q_ibendportcons

    def test_name_exact(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Ibendportcon query with exact name match."""
        q = setools.IbendportconQuery(compiled_policy, name="test1", name_regex=False)

        ibendportcons = sorted(n.name for n in q.results())
        assert ["test1"] == ibendportcons

    def test_name_regext(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Ibendportcon query with regex name match."""
        q = setools.IbendportconQuery(compiled_policy, name="test2(a|b)", name_regex=True)

        ibendportcons = sorted(n.name for n in q.results())
        assert ["test2a", "test2b"] == ibendportcons

    def test_port(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Ibendportcon query with port match."""
        q = setools.IbendportconQuery(compiled_policy, port=10)

        ibendportcons = sorted(n.name for n in q.results())
        assert ["test10"] == ibendportcons

    def test_user_exact(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Ibendportcon query with context user exact match"""
        q = setools.IbendportconQuery(compiled_policy, user="user20", user_regex=False)

        ibendportcons = sorted(n.name for n in q.results())
        assert ["test20"] == ibendportcons

    def test_user_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Ibendportcon query with context user regex match"""
        q = setools.IbendportconQuery(compiled_policy, user="user21(a|b)", user_regex=True)

        ibendportcons = sorted(n.name for n in q.results())
        assert ["test21a", "test21b"] == ibendportcons

    def test_role_exact(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Ibendportcon query with context role exact match"""
        q = setools.IbendportconQuery(compiled_policy, role="role30_r", role_regex=False)

        ibendportcons = sorted(n.name for n in q.results())
        assert ["test30"] == ibendportcons

    def test_role_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Ibendportcon query with context role regex match"""
        q = setools.IbendportconQuery(compiled_policy, role="role31(a|c)_r", role_regex=True)

        ibendportcons = sorted(n.name for n in q.results())
        assert ["test31a", "test31c"] == ibendportcons

    def test_type_exact(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Ibendportcon query with context type exact match"""
        q = setools.IbendportconQuery(compiled_policy, type_="type40", type_regex=False)

        ibendportcons = sorted(n.name for n in q.results())
        assert ["test40"] == ibendportcons

    def test_type_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Ibendportcon query with context type regex match"""
        q = setools.IbendportconQuery(compiled_policy, type_="type41(b|c)", type_regex=True)

        ibendportcons = sorted(n.name for n in q.results())
        assert ["test41b", "test41c"] == ibendportcons

    def test_range_exact(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Ibendportcon query with context range exact match"""
        q = setools.IbendportconQuery(compiled_policy, range_="s0:c1 - s0:c0.c4")

        ibendportcons = sorted(n.name for n in q.results())
        assert ["test50"] == ibendportcons

    def test_range_overlap1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Ibendportcon query with context range overlap match (equal)"""
        q = setools.IbendportconQuery(compiled_policy, range_="s1:c1 - s1:c0.c4",
                                      range_overlap=True)

        ibendportcons = sorted(n.name for n in q.results())
        assert ["test51"] == ibendportcons

    def test_range_overlap2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Ibendportcon query with context range overlap match (subset)"""
        q = setools.IbendportconQuery(compiled_policy, range_="s1:c1,c2 - s1:c0.c3",
                                      range_overlap=True)

        ibendportcons = sorted(n.name for n in q.results())
        assert ["test51"] == ibendportcons

    def test_range_overlap3(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Ibendportcon query with context range overlap match (superset)"""
        q = setools.IbendportconQuery(compiled_policy, range_="s1 - s1:c0.c4", range_overlap=True)

        ibendportcons = sorted(n.name for n in q.results())
        assert ["test51"] == ibendportcons

    def test_range_overlap4(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Ibendportcon query with context range overlap match (overlap low level)"""
        q = setools.IbendportconQuery(compiled_policy, range_="s1 - s1:c1,c2", range_overlap=True)

        ibendportcons = sorted(n.name for n in q.results())
        assert ["test51"] == ibendportcons

    def test_range_overlap5(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Ibendportcon query with context range overlap match (overlap high level)"""
        q = setools.IbendportconQuery(compiled_policy, range_="s1:c1,c2 - s1:c0.c4",
                                      range_overlap=True)

        ibendportcons = sorted(n.name for n in q.results())
        assert ["test51"] == ibendportcons

    def test_range_subset1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Ibendportcon query with context range subset match"""
        q = setools.IbendportconQuery(compiled_policy, range_="s2:c1,c2 - s2:c0.c3",
                                      range_overlap=True)

        ibendportcons = sorted(n.name for n in q.results())
        assert ["test52"] == ibendportcons

    def test_range_subset2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Ibendportcon query with context range subset match (equal)"""
        q = setools.IbendportconQuery(compiled_policy, range_="s2:c1 - s2:c1.c3",
                                      range_overlap=True)

        ibendportcons = sorted(n.name for n in q.results())
        assert ["test52"] == ibendportcons

    def test_range_superset1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Ibendportcon query with context range superset match"""
        q = setools.IbendportconQuery(compiled_policy, range_="s3 - s3:c0.c4", range_superset=True)

        ibendportcons = sorted(n.name for n in q.results())
        assert ["test53"] == ibendportcons

    def test_range_superset2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Ibendportcon query with context range superset match (equal)"""
        q = setools.IbendportconQuery(compiled_policy, range_="s3:c1 - s3:c1.c3",
                                      range_superset=True)

        ibendportcons = sorted(n.name for n in q.results())
        assert ["test53"] == ibendportcons

    def test_range_proper_subset1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Ibendportcon query with context range proper subset match"""
        q = setools.IbendportconQuery(compiled_policy, range_="s4:c1,c2", range_subset=True,
                                      range_proper=True)

        ibendportcons = sorted(n.name for n in q.results())
        assert ["test54"] == ibendportcons

    def test_range_proper_subset2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Ibendportcon query with context range proper subset match (equal)"""
        q = setools.IbendportconQuery(compiled_policy, range_="s4:c1 - s4:c1.c3",
                                      range_subset=True, range_proper=True)

        ibendportcons = sorted(n.name for n in q.results())
        assert [] == ibendportcons

    def test_range_proper_subset3(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Ibendportcon query with context range proper subset match (equal low only)"""
        q = setools.IbendportconQuery(compiled_policy, range_="s4:c1 - s4:c1.c2",
                                      range_subset=True, range_proper=True)

        ibendportcons = sorted(n.name for n in q.results())
        assert ["test54"] == ibendportcons

    def test_range_proper_subset4(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Ibendportcon query with context range proper subset match (equal high only)"""
        q = setools.IbendportconQuery(compiled_policy, range_="s4:c1,c2 - s4:c1.c3",
                                      range_subset=True, range_proper=True)

        ibendportcons = sorted(n.name for n in q.results())
        assert ["test54"] == ibendportcons

    def test_range_proper_superset1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Ibendportcon query with context range proper superset match"""
        q = setools.IbendportconQuery(compiled_policy, range_="s5 - s5:c0.c4", range_superset=True,
                                      range_proper=True)

        ibendportcons = sorted(n.name for n in q.results())
        assert ["test55"] == ibendportcons

    def test_range_proper_superset2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Ibendportcon query with context range proper superset match (equal)"""
        q = setools.IbendportconQuery(compiled_policy, range_="s5:c1 - s5:c1.c3",
                                      range_superset=True, range_proper=True)

        ibendportcons = sorted(n.name for n in q.results())
        assert [] == ibendportcons

    def test_range_proper_superset3(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Ibendportcon query with context range proper superset match (equal low)"""
        q = setools.IbendportconQuery(compiled_policy, range_="s5:c1 - s5:c1.c4",
                                      range_superset=True, range_proper=True)

        ibendportcons = sorted(n.name for n in q.results())
        assert ["test55"] == ibendportcons

    def test_range_proper_superset4(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Ibendportcon query with context range proper superset match (equal high)"""
        q = setools.IbendportconQuery(compiled_policy, range_="s5 - s5:c1.c3", range_superset=True,
                                      range_proper=True)

        ibendportcons = sorted(n.name for n in q.results())
        assert ["test55"] == ibendportcons
