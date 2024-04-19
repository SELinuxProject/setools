# Copyright 2014, Tresys Technology, LLC
#
# SPDX-License-Identifier: GPL-2.0-only
#
import pytest
import setools


@pytest.mark.obj_args("tests/library/netifconquery.conf")
class TestNetifconQuery:

    def test_unset(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Netifcon query with no criteria"""
        # query with no parameters gets all netifs.
        netifs = sorted(compiled_policy.netifcons())

        q = setools.NetifconQuery(compiled_policy)
        q_netifs = sorted(q.results())

        assert netifs == q_netifs

    def test_name_exact(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Netifcon query with exact match"""
        q = setools.NetifconQuery(compiled_policy, name="test1", name_regex=False)

        netifs = sorted(s.netif for s in q.results())
        assert ["test1"] == netifs

    def test_name_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Netifcon query with regex match"""
        q = setools.NetifconQuery(compiled_policy, name="test2(a|b)", name_regex=True)

        netifs = sorted(s.netif for s in q.results())
        assert ["test2a", "test2b"] == netifs

    def test_user_exact(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Netifcon query with context user exact match"""
        q = setools.NetifconQuery(compiled_policy, user="user10", user_regex=False)

        netifs = sorted(s.netif for s in q.results())
        assert ["test10"] == netifs

    def test_user_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Netifcon query with context user regex match"""
        q = setools.NetifconQuery(compiled_policy, user="user11(a|b)", user_regex=True)

        netifs = sorted(s.netif for s in q.results())
        assert ["test11a", "test11b"] == netifs

    def test_role_exact(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Netifcon query with context role exact match"""
        q = setools.NetifconQuery(compiled_policy, role="role20_r", role_regex=False)

        netifs = sorted(s.netif for s in q.results())
        assert ["test20"] == netifs

    def test_role_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Netifcon query with context role regex match"""
        q = setools.NetifconQuery(compiled_policy, role="role21(a|c)_r", role_regex=True)

        netifs = sorted(s.netif for s in q.results())
        assert ["test21a", "test21c"] == netifs

    def test_type_exact(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Netifcon query with context type exact match"""
        q = setools.NetifconQuery(compiled_policy, type_="type30", type_regex=False)

        netifs = sorted(s.netif for s in q.results())
        assert ["test30"] == netifs

    def test_type_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Netifcon query with context type regex match"""
        q = setools.NetifconQuery(compiled_policy, type_="type31(b|c)", type_regex=True)

        netifs = sorted(s.netif for s in q.results())
        assert ["test31b", "test31c"] == netifs

    def test_range_exact(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Netifcon query with context range exact match"""
        q = setools.NetifconQuery(compiled_policy, range_="s0:c1 - s0:c0.c4")

        netifs = sorted(s.netif for s in q.results())
        assert ["test40"] == netifs

    def test_range_overlap1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Netifcon query with context range overlap match (equal)"""
        q = setools.NetifconQuery(compiled_policy, range_="s1:c1 - s1:c0.c4", range_overlap=True)

        netifs = sorted(s.netif for s in q.results())
        assert ["test41"] == netifs

    def test_range_overlap2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Netifcon query with context range overlap match (subset)"""
        q = setools.NetifconQuery(compiled_policy, range_="s1:c1,c2 - s1:c0.c3",
                                  range_overlap=True)

        netifs = sorted(s.netif for s in q.results())
        assert ["test41"] == netifs

    def test_range_overlap3(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Netifcon query with context range overlap match (superset)"""
        q = setools.NetifconQuery(compiled_policy, range_="s1 - s1:c0.c4", range_overlap=True)

        netifs = sorted(s.netif for s in q.results())
        assert ["test41"] == netifs

    def test_range_overlap4(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Netifcon query with context range overlap match (overlap low level)"""
        q = setools.NetifconQuery(compiled_policy, range_="s1 - s1:c1,c2", range_overlap=True)

        netifs = sorted(s.netif for s in q.results())
        assert ["test41"] == netifs

    def test_range_overlap5(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Netifcon query with context range overlap match (overlap high level)"""
        q = setools.NetifconQuery(compiled_policy, range_="s1:c1,c2 - s1:c0.c4",
                                  range_overlap=True)

        netifs = sorted(s.netif for s in q.results())
        assert ["test41"] == netifs

    def test_range_subset1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Netifcon query with context range subset match"""
        q = setools.NetifconQuery(compiled_policy, range_="s2:c1,c2 - s2:c0.c3",
                                  range_overlap=True)

        netifs = sorted(s.netif for s in q.results())
        assert ["test42"] == netifs

    def test_range_subset2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Netifcon query with context range subset match (equal)"""
        q = setools.NetifconQuery(compiled_policy, range_="s2:c1 - s2:c1.c3", range_overlap=True)

        netifs = sorted(s.netif for s in q.results())
        assert ["test42"] == netifs

    def test_range_superset1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Netifcon query with context range superset match"""
        q = setools.NetifconQuery(compiled_policy, range_="s3 - s3:c0.c4", range_superset=True)

        netifs = sorted(s.netif for s in q.results())
        assert ["test43"] == netifs

    def test_range_superset2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Netifcon query with context range superset match (equal)"""
        q = setools.NetifconQuery(compiled_policy, range_="s3:c1 - s3:c1.c3", range_superset=True)

        netifs = sorted(s.netif for s in q.results())
        assert ["test43"] == netifs

    def test_range_proper_subset1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Netifcon query with context range proper subset match"""
        q = setools.NetifconQuery(compiled_policy, range_="s4:c1,c2", range_subset=True,
                                  range_proper=True)

        netifs = sorted(s.netif for s in q.results())
        assert ["test44"] == netifs

    def test_range_proper_subset2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Netifcon query with context range proper subset match (equal)"""
        q = setools.NetifconQuery(compiled_policy, range_="s4:c1 - s4:c1.c3", range_subset=True,
                                  range_proper=True)

        netifs = sorted(s.netif for s in q.results())
        assert [] == netifs

    def test_range_proper_subset3(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Netifcon query with context range proper subset match (equal low only)"""
        q = setools.NetifconQuery(compiled_policy, range_="s4:c1 - s4:c1.c2", range_subset=True,
                                  range_proper=True)

        netifs = sorted(s.netif for s in q.results())
        assert ["test44"] == netifs

    def test_range_proper_subset4(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Netifcon query with context range proper subset match (equal high only)"""
        q = setools.NetifconQuery(compiled_policy, range_="s4:c1,c2 - s4:c1.c3", range_subset=True,
                                  range_proper=True)

        netifs = sorted(s.netif for s in q.results())
        assert ["test44"] == netifs

    def test_range_proper_superset1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Netifcon query with context range proper superset match"""
        q = setools.NetifconQuery(compiled_policy, range_="s5 - s5:c0.c4", range_superset=True,
                                  range_proper=True)

        netifs = sorted(s.netif for s in q.results())
        assert ["test45"] == netifs

    def test_range_proper_superset2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Netifcon query with context range proper superset match (equal)"""
        q = setools.NetifconQuery(compiled_policy, range_="s5:c1 - s5:c1.c3", range_superset=True,
                                  range_proper=True)

        netifs = sorted(s.netif for s in q.results())
        assert [] == netifs

    def test_range_proper_superset3(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Netifcon query with context range proper superset match (equal low)"""
        q = setools.NetifconQuery(compiled_policy, range_="s5:c1 - s5:c1.c4", range_superset=True,
                                  range_proper=True)

        netifs = sorted(s.netif for s in q.results())
        assert ["test45"] == netifs

    def test_range_proper_superset4(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Netifcon query with context range proper superset match (equal high)"""
        q = setools.NetifconQuery(compiled_policy, range_="s5 - s5:c1.c3", range_superset=True,
                                  range_proper=True)

        netifs = sorted(s.netif for s in q.results())
        assert ["test45"] == netifs
