# Derived from tests/portconquery.py
#
# SPDX-License-Identifier: GPL-2.0-only
#
import pytest
import setools


@pytest.mark.obj_args("tests/library/iomemconquery.conf", xen=True)
class TestIomemconQuery:

    def test_unset(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Iomemcon query with no criteria"""
        # query with no parameters gets all addr.
        rules = sorted(compiled_policy.iomemcons())

        q = setools.IomemconQuery(compiled_policy)
        q_rules = sorted(q.results())

        assert rules == q_rules

    def test_user_exact(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Iomemcon query with context user exact match"""
        q = setools.IomemconQuery(compiled_policy, user="user10", user_regex=False)

        addr = sorted(p.addr for p in q.results())
        assert [setools.IomemconRange(10, 10)] == addr

    def test_user_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Iomemcon query with context user regex match"""
        q = setools.IomemconQuery(compiled_policy, user="user11(a|b)", user_regex=True)

        addr = sorted(p.addr for p in q.results())
        assert [setools.IomemconRange(11, 11), setools.IomemconRange(11000, 11000)] == addr

    def test_role_exact(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Iomemcon query with context role exact match"""
        q = setools.IomemconQuery(compiled_policy, role="role20_r", role_regex=False)

        addr = sorted(p.addr for p in q.results())
        assert [setools.IomemconRange(20, 20)] == addr

    def test_role_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Iomemcon query with context role regex match"""
        q = setools.IomemconQuery(compiled_policy, role="role21(a|c)_r", role_regex=True)

        addr = sorted(p.addr for p in q.results())
        assert [setools.IomemconRange(21, 21), setools.IomemconRange(21001, 21001)] == addr

    def test_type_exact(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Iomemcon query with context type exact match"""
        q = setools.IomemconQuery(compiled_policy, type_="type30", type_regex=False)

        addr = sorted(p.addr for p in q.results())
        assert [setools.IomemconRange(30, 30)] == addr

    def test_type_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Iomemcon query with context type regex match"""
        q = setools.IomemconQuery(compiled_policy, type_="type31(b|c)", type_regex=True)

        addr = sorted(p.addr for p in q.results())
        assert [setools.IomemconRange(31000, 31000), setools.IomemconRange(31001, 31001)] == addr

    def test_range_exact(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Iomemcon query with context range exact match"""
        q = setools.IomemconQuery(compiled_policy, range_="s0:c1 - s0:c0.c4")

        addr = sorted(p.addr for p in q.results())
        assert [setools.IomemconRange(40, 40)] == addr

    def test_range_overlap1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Iomemcon query with context range overlap match (equal)"""
        q = setools.IomemconQuery(compiled_policy, range_="s1:c1 - s1:c0.c4", range_overlap=True)

        addr = sorted(p.addr for p in q.results())
        assert [setools.IomemconRange(41, 41)] == addr

    def test_range_overlap2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Iomemcon query with context range overlap match (subset)"""
        q = setools.IomemconQuery(compiled_policy, range_="s1:c1,c2 - s1:c0.c3",
                                  range_overlap=True)

        addr = sorted(p.addr for p in q.results())
        assert [setools.IomemconRange(41, 41)] == addr

    def test_range_overlap3(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Iomemcon query with context range overlap match (superset)"""
        q = setools.IomemconQuery(compiled_policy, range_="s1 - s1:c0.c4", range_overlap=True)

        addr = sorted(p.addr for p in q.results())
        assert [setools.IomemconRange(41, 41)] == addr

    def test_range_overlap4(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Iomemcon query with context range overlap match (overlap low level)"""
        q = setools.IomemconQuery(compiled_policy, range_="s1 - s1:c1,c2", range_overlap=True)

        addr = sorted(p.addr for p in q.results())
        assert [setools.IomemconRange(41, 41)] == addr

    def test_range_overlap5(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Iomemcon query with context range overlap match (overlap high level)"""
        q = setools.IomemconQuery(compiled_policy, range_="s1:c1,c2 - s1:c0.c4",
                                  range_overlap=True)

        addr = sorted(p.addr for p in q.results())
        assert [setools.IomemconRange(41, 41)] == addr

    def test_range_subset1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Iomemcon query with context range subset match"""
        q = setools.IomemconQuery(compiled_policy, range_="s2:c1,c2 - s2:c0.c3",
                                  range_overlap=True)

        addr = sorted(p.addr for p in q.results())
        assert [setools.IomemconRange(42, 42)] == addr

    def test_range_subset2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Iomemcon query with context range subset match (equal)"""
        q = setools.IomemconQuery(compiled_policy, range_="s2:c1 - s2:c1.c3", range_overlap=True)

        addr = sorted(p.addr for p in q.results())
        assert [setools.IomemconRange(42, 42)] == addr

    def test_range_superset1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Iomemcon query with context range superset match"""
        q = setools.IomemconQuery(compiled_policy, range_="s3 - s3:c0.c4", range_superset=True)

        addr = sorted(p.addr for p in q.results())
        assert [setools.IomemconRange(43, 43)] == addr

    def test_range_superset2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Iomemcon query with context range superset match (equal)"""
        q = setools.IomemconQuery(compiled_policy, range_="s3:c1 - s3:c1.c3", range_superset=True)

        addr = sorted(p.addr for p in q.results())
        assert [setools.IomemconRange(43, 43)] == addr

    def test_range_proper_subset1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Iomemcon query with context range proper subset match"""
        q = setools.IomemconQuery(compiled_policy, range_="s4:c1,c2", range_subset=True,
                                  range_proper=True)

        addr = sorted(p.addr for p in q.results())
        assert [setools.IomemconRange(44, 44)] == addr

    def test_range_proper_subset2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Iomemcon query with context range proper subset match (equal)"""
        q = setools.IomemconQuery(compiled_policy, range_="s4:c1 - s4:c1.c3", range_subset=True,
                                  range_proper=True)

        addr = sorted(p.addr for p in q.results())
        assert [] == addr

    def test_range_proper_subset3(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Iomemcon query with context range proper subset match (equal low only)"""
        q = setools.IomemconQuery(compiled_policy, range_="s4:c1 - s4:c1.c2", range_subset=True,
                                  range_proper=True)

        addr = sorted(p.addr for p in q.results())
        assert [setools.IomemconRange(44, 44)] == addr

    def test_range_proper_subset4(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Iomemcon query with context range proper subset match (equal high only)"""
        q = setools.IomemconQuery(compiled_policy, range_="s4:c1,c2 - s4:c1.c3",
                                  range_subset=True, range_proper=True)

        addr = sorted(p.addr for p in q.results())
        assert [setools.IomemconRange(44, 44)] == addr

    def test_range_proper_superset1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Iomemcon query with context range proper superset match"""
        q = setools.IomemconQuery(compiled_policy, range_="s5 - s5:c0.c4", range_superset=True,
                                  range_proper=True)

        addr = sorted(p.addr for p in q.results())
        assert [setools.IomemconRange(45, 45)] == addr

    def test_range_proper_superset2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Iomemcon query with context range proper superset match (equal)"""
        q = setools.IomemconQuery(compiled_policy, range_="s5:c1 - s5:c1.c3", range_superset=True,
                                  range_proper=True)

        addr = sorted(p.addr for p in q.results())
        assert [] == addr

    def test_range_proper_superset3(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Iomemcon query with context range proper superset match (equal low)"""
        q = setools.IomemconQuery(compiled_policy, range_="s5:c1 - s5:c1.c4", range_superset=True,
                                  range_proper=True)

        addr = sorted(p.addr for p in q.results())
        assert [setools.IomemconRange(45, 45)] == addr

    def test_range_proper_superset4(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Iomemcon query with context range proper superset match (equal high)"""
        q = setools.IomemconQuery(compiled_policy, range_="s5 - s5:c1.c3", range_superset=True,
                                  range_proper=True)

        addr = sorted(p.addr for p in q.results())
        assert [setools.IomemconRange(45, 45)] == addr

    def test_single_equal(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Iomemcon query with single mem addr exact match"""
        q = setools.IomemconQuery(compiled_policy, addr=(50, 50))

        addr = sorted(p.addr for p in q.results())
        assert [setools.IomemconRange(50, 50)] == addr

    def test_range_equal(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Iomemcon query with mem addr range exact match"""
        q = setools.IomemconQuery(compiled_policy, addr=(50100, 50110))

        addr = sorted(p.addr for p in q.results())
        assert [setools.IomemconRange(50100, 50110)] == addr

    def test_single_subset(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Iomemcon query with single mem addr subset"""
        q = setools.IomemconQuery(compiled_policy, addr=(50200, 50200), addr_subset=True)

        addr = sorted(p.addr for p in q.results())
        assert [setools.IomemconRange(50200, 50200)] == addr

    def test_range_subset(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Iomemcon query with range subset"""
        q = setools.IomemconQuery(compiled_policy, addr=(50301, 50309), addr_subset=True)

        addr = sorted(p.addr for p in q.results())
        assert [setools.IomemconRange(50300, 50310)] == addr

    def test_range_subset_edge1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Iomemcon query with range subset, equal edge case"""
        q = setools.IomemconQuery(compiled_policy, addr=(50300, 50310), addr_subset=True)

        addr = sorted(p.addr for p in q.results())
        assert [setools.IomemconRange(50300, 50310)] == addr

    def test_single_proper_subset(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Iomemcon query with single mem addr proper subset"""
        q = setools.IomemconQuery(
            compiled_policy, addr=(50400, 50400), addr_subset=True, addr_proper=True)

        addr = sorted(p.addr for p in q.results())
        assert [] == addr

    def test_range_proper_subset(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Iomemcon query with range proper subset"""
        q = setools.IomemconQuery(
            compiled_policy, addr=(50501, 50509), addr_subset=True, addr_proper=True)

        addr = sorted(p.addr for p in q.results())
        assert [setools.IomemconRange(50500, 50510)] == addr

    def test_range_proper_subset_edge1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Iomemcon query with range proper subset, equal edge case"""
        q = setools.IomemconQuery(
            compiled_policy, addr=(50500, 50510), addr_subset=True, addr_proper=True)

        addr = sorted(p.addr for p in q.results())
        assert [] == addr

    def test_range_proper_subset_edge2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Iomemcon query with range proper subset, low equal edge case"""
        q = setools.IomemconQuery(
            compiled_policy, addr=(50500, 50509), addr_subset=True, addr_proper=True)

        addr = sorted(p.addr for p in q.results())
        assert [setools.IomemconRange(50500, 50510)] == addr

    def test_range_proper_subset_edge3(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Iomemcon query with range proper subset, high equal edge case"""
        q = setools.IomemconQuery(
            compiled_policy, addr=(50501, 50510), addr_subset=True, addr_proper=True)

        addr = sorted(p.addr for p in q.results())
        assert [setools.IomemconRange(50500, 50510)] == addr

    def test_single_superset(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Iomemcon query with single mem addr superset"""
        q = setools.IomemconQuery(compiled_policy, addr=(50600, 50602), addr_superset=True)

        addr = sorted(p.addr for p in q.results())
        assert [setools.IomemconRange(50601, 50601)] == addr

    def test_single_superset_edge1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Iomemcon query with single mem addr superset, equal edge case"""
        q = setools.IomemconQuery(compiled_policy, addr=(50601, 50601), addr_superset=True)

        addr = sorted(p.addr for p in q.results())
        assert [setools.IomemconRange(50601, 50601)] == addr

    def test_range_superset(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Iomemcon query with range superset"""
        q = setools.IomemconQuery(compiled_policy, addr=(50700, 50711), addr_superset=True)

        addr = sorted(p.addr for p in q.results())
        assert [setools.IomemconRange(50700, 50710)] == addr

    def test_range_superset_edge1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Iomemcon query with range superset, equal edge case"""
        q = setools.IomemconQuery(compiled_policy, addr=(50700, 50710), addr_superset=True)

        addr = sorted(p.addr for p in q.results())
        assert [setools.IomemconRange(50700, 50710)] == addr

    def test_single_proper_superset(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Iomemcon query with single mem addr proper superset"""
        q = setools.IomemconQuery(
            compiled_policy, addr=(50800, 50802), addr_superset=True, addr_proper=True)

        addr = sorted(p.addr for p in q.results())
        assert [setools.IomemconRange(50801, 50801)] == addr

    def test_single_proper_superset_edge1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Iomemcon query with single mem addr proper superset, equal edge case"""
        q = setools.IomemconQuery(
            compiled_policy, addr=(50801, 50801), addr_superset=True, addr_proper=True)

        addr = sorted(p.addr for p in q.results())
        assert [] == addr

    def test_single_proper_superset_edge2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Iomemcon query with single mem addr proper superset, low equal edge case"""
        q = setools.IomemconQuery(
            compiled_policy, addr=(50801, 50802), addr_superset=True, addr_proper=True)

        addr = sorted(p.addr for p in q.results())
        assert [setools.IomemconRange(50801, 50801)] == addr

    def test_single_proper_superset_edge3(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Iomemcon query with single mem addr proper superset, high equal edge case"""
        q = setools.IomemconQuery(
            compiled_policy, addr=(50800, 50801), addr_superset=True, addr_proper=True)

        addr = sorted(p.addr for p in q.results())
        assert [setools.IomemconRange(50801, 50801)] == addr

    def test_range_proper_superset(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Iomemcon query with range proper superset"""
        q = setools.IomemconQuery(
            compiled_policy, addr=(50900, 50911), addr_superset=True, addr_proper=True)

        addr = sorted(p.addr for p in q.results())
        assert [setools.IomemconRange(50901, 50910)] == addr

    def test_range_proper_superset_edge1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Iomemcon query with range proper superset, equal edge case"""
        q = setools.IomemconQuery(
            compiled_policy, addr=(50901, 50910), addr_superset=True, addr_proper=True)

        addr = sorted(p.addr for p in q.results())
        assert [] == addr

    def test_range_proper_superset_edge2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Iomemcon query with range proper superset, equal high mem addr edge case"""
        q = setools.IomemconQuery(
            compiled_policy, addr=(50900, 50910), addr_superset=True, addr_proper=True)

        addr = sorted(p.addr for p in q.results())
        assert [setools.IomemconRange(50901, 50910)] == addr

    def test_range_proper_superset_edge3(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Iomemcon query with range proper superset, equal low mem addr edge case"""
        q = setools.IomemconQuery(
            compiled_policy, addr=(50901, 50911), addr_superset=True, addr_proper=True)

        addr = sorted(p.addr for p in q.results())
        assert [setools.IomemconRange(50901, 50910)] == addr

    def test_single_overlap(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Iomemcon query with single overlap"""
        q = setools.IomemconQuery(compiled_policy, addr=(60001, 60001), addr_overlap=True)

        addr = sorted(p.addr for p in q.results())
        assert [setools.IomemconRange(60001, 60001)] == addr

    def test_single_overlap_edge1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Iomemcon query with single overlap, range match low"""
        q = setools.IomemconQuery(compiled_policy, addr=(60001, 60002), addr_overlap=True)

        addr = sorted(p.addr for p in q.results())
        assert [setools.IomemconRange(60001, 60001)] == addr

    def test_single_overlap_edge2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Iomemcon query with single overlap, range match high"""
        q = setools.IomemconQuery(compiled_policy, addr=(60000, 60001), addr_overlap=True)

        addr = sorted(p.addr for p in q.results())
        assert [setools.IomemconRange(60001, 60001)] == addr

    def test_single_overlap_edge3(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Iomemcon query with single overlap, range match proper superset"""
        q = setools.IomemconQuery(compiled_policy, addr=(60000, 60002), addr_overlap=True)

        addr = sorted(p.addr for p in q.results())
        assert [setools.IomemconRange(60001, 60001)] == addr

    def test_range_overlap_low_half(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Iomemcon query with range overlap, low half match"""
        q = setools.IomemconQuery(compiled_policy, addr=(60100, 60105), addr_overlap=True)

        addr = sorted(p.addr for p in q.results())
        assert [setools.IomemconRange(60101, 60110)] == addr

    def test_range_overlap_high_half(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Iomemcon query with range overlap, high half match"""
        q = setools.IomemconQuery(compiled_policy, addr=(60205, 60211), addr_overlap=True)

        addr = sorted(p.addr for p in q.results())
        assert [setools.IomemconRange(60200, 60210)] == addr

    def test_range_overlap_middle(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Iomemcon query with range overlap, middle match"""
        q = setools.IomemconQuery(compiled_policy, addr=(60305, 60308), addr_overlap=True)

        addr = sorted(p.addr for p in q.results())
        assert [setools.IomemconRange(60300, 60310)] == addr

    def test_range_overlap_equal(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Iomemcon query with range overlap, equal match"""
        q = setools.IomemconQuery(compiled_policy, addr=(60400, 60410), addr_overlap=True)

        addr = sorted(p.addr for p in q.results())
        assert [setools.IomemconRange(60400, 60410)] == addr

    def test_range_overlap_superset(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Iomemcon query with range overlap, superset match"""
        q = setools.IomemconQuery(compiled_policy, addr=(60500, 60510), addr_overlap=True)

        addr = sorted(p.addr for p in q.results())
        assert [setools.IomemconRange(60501, 60509)] == addr
