# Copyright 2014, Tresys Technology, LLC
#
# SPDX-License-Identifier: GPL-2.0-only
#
from socket import IPPROTO_UDP

import pytest
import setools


@pytest.mark.obj_args("tests/library/portconquery.conf")
class TestPortconQuery:

    def test_unset(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with no criteria"""
        # query with no parameters gets all ports.
        rules = sorted(compiled_policy.portcons())

        q = setools.PortconQuery(compiled_policy)
        q_rules = sorted(q.results())

        assert rules == q_rules

    def test_protocol(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with protocol match"""
        q = setools.PortconQuery(compiled_policy, protocol=IPPROTO_UDP)

        ports = sorted(p.ports for p in q.results())
        assert [setools.PortconRange(1, 1)] == ports

    def test_user_exact(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with context user exact match"""
        q = setools.PortconQuery(compiled_policy, user="user10", user_regex=False)

        ports = sorted(p.ports for p in q.results())
        assert [setools.PortconRange(10, 10)] == ports

    def test_user_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with context user regex match"""
        q = setools.PortconQuery(compiled_policy, user="user11(a|b)", user_regex=True)

        ports = sorted(p.ports for p in q.results())
        assert [setools.PortconRange(11, 11), setools.PortconRange(11000, 11000)] == ports

    def test_role_exact(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with context role exact match"""
        q = setools.PortconQuery(compiled_policy, role="role20_r", role_regex=False)

        ports = sorted(p.ports for p in q.results())
        assert [setools.PortconRange(20, 20)] == ports

    def test_role_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with context role regex match"""
        q = setools.PortconQuery(compiled_policy, role="role21(a|c)_r", role_regex=True)

        ports = sorted(p.ports for p in q.results())
        assert [setools.PortconRange(21, 21), setools.PortconRange(21001, 21001)] == ports

    def test_type_exact(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with context type exact match"""
        q = setools.PortconQuery(compiled_policy, type_="type30", type_regex=False)

        ports = sorted(p.ports for p in q.results())
        assert [setools.PortconRange(30, 30)] == ports

    def test_type_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with context type regex match"""
        q = setools.PortconQuery(compiled_policy, type_="type31(b|c)", type_regex=True)

        ports = sorted(p.ports for p in q.results())
        assert [setools.PortconRange(31000, 31000), setools.PortconRange(31001, 31001)] == ports

    def test_range_exact(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with context range exact match"""
        q = setools.PortconQuery(compiled_policy, range_="s0:c1 - s0:c0.c4")

        ports = sorted(p.ports for p in q.results())
        assert [setools.PortconRange(40, 40)] == ports

    def test_range_overlap1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with context range overlap match (equal)"""
        q = setools.PortconQuery(compiled_policy, range_="s1:c1 - s1:c0.c4", range_overlap=True)

        ports = sorted(p.ports for p in q.results())
        assert [setools.PortconRange(41, 41)] == ports

    def test_range_overlap2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with context range overlap match (subset)"""
        q = setools.PortconQuery(compiled_policy, range_="s1:c1,c2 - s1:c0.c3", range_overlap=True)

        ports = sorted(p.ports for p in q.results())
        assert [setools.PortconRange(41, 41)] == ports

    def test_range_overlap3(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with context range overlap match (superset)"""
        q = setools.PortconQuery(compiled_policy, range_="s1 - s1:c0.c4", range_overlap=True)

        ports = sorted(p.ports for p in q.results())
        assert [setools.PortconRange(41, 41)] == ports

    def test_range_overlap4(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with context range overlap match (overlap low level)"""
        q = setools.PortconQuery(compiled_policy, range_="s1 - s1:c1,c2", range_overlap=True)

        ports = sorted(p.ports for p in q.results())
        assert [setools.PortconRange(41, 41)] == ports

    def test_range_overlap5(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with context range overlap match (overlap high level)"""
        q = setools.PortconQuery(compiled_policy, range_="s1:c1,c2 - s1:c0.c4", range_overlap=True)

        ports = sorted(p.ports for p in q.results())
        assert [setools.PortconRange(41, 41)] == ports

    def test_range_subset1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with context range subset match"""
        q = setools.PortconQuery(compiled_policy, range_="s2:c1,c2 - s2:c0.c3", range_overlap=True)

        ports = sorted(p.ports for p in q.results())
        assert [setools.PortconRange(42, 42)] == ports

    def test_range_subset2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with context range subset match (equal)"""
        q = setools.PortconQuery(compiled_policy, range_="s2:c1 - s2:c1.c3", range_overlap=True)

        ports = sorted(p.ports for p in q.results())
        assert [setools.PortconRange(42, 42)] == ports

    def test_range_superset1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with context range superset match"""
        q = setools.PortconQuery(compiled_policy, range_="s3 - s3:c0.c4", range_superset=True)

        ports = sorted(p.ports for p in q.results())
        assert [setools.PortconRange(43, 43)] == ports

    def test_range_superset2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with context range superset match (equal)"""
        q = setools.PortconQuery(compiled_policy, range_="s3:c1 - s3:c1.c3", range_superset=True)

        ports = sorted(p.ports for p in q.results())
        assert [setools.PortconRange(43, 43)] == ports

    def test_range_proper_subset1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with context range proper subset match"""
        q = setools.PortconQuery(compiled_policy, range_="s4:c1,c2", range_subset=True,
                                 range_proper=True)

        ports = sorted(p.ports for p in q.results())
        assert [setools.PortconRange(44, 44)] == ports

    def test_range_proper_subset2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with context range proper subset match (equal)"""
        q = setools.PortconQuery(compiled_policy, range_="s4:c1 - s4:c1.c3", range_subset=True,
                                 range_proper=True)

        ports = sorted(p.ports for p in q.results())
        assert [] == ports

    def test_range_proper_subset3(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with context range proper subset match (equal low only)"""
        q = setools.PortconQuery(compiled_policy, range_="s4:c1 - s4:c1.c2", range_subset=True,
                                 range_proper=True)

        ports = sorted(p.ports for p in q.results())
        assert [setools.PortconRange(44, 44)] == ports

    def test_range_proper_subset4(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with context range proper subset match (equal high only)"""
        q = setools.PortconQuery(compiled_policy, range_="s4:c1,c2 - s4:c1.c3", range_subset=True,
                                 range_proper=True)

        ports = sorted(p.ports for p in q.results())
        assert [setools.PortconRange(44, 44)] == ports

    def test_range_proper_superset1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with context range proper superset match"""
        q = setools.PortconQuery(compiled_policy, range_="s5 - s5:c0.c4", range_superset=True,
                                 range_proper=True)

        ports = sorted(p.ports for p in q.results())
        assert [setools.PortconRange(45, 45)] == ports

    def test_range_proper_superset2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with context range proper superset match (equal)"""
        q = setools.PortconQuery(compiled_policy, range_="s5:c1 - s5:c1.c3", range_superset=True,
                                 range_proper=True)

        ports = sorted(p.ports for p in q.results())
        assert [] == ports

    def test_range_proper_superset3(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with context range proper superset match (equal low)"""
        q = setools.PortconQuery(compiled_policy, range_="s5:c1 - s5:c1.c4", range_superset=True,
                                 range_proper=True)

        ports = sorted(p.ports for p in q.results())
        assert [setools.PortconRange(45, 45)] == ports

    def test_range_proper_superset4(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with context range proper superset match (equal high)"""
        q = setools.PortconQuery(compiled_policy, range_="s5 - s5:c1.c3", range_superset=True,
                                 range_proper=True)

        ports = sorted(p.ports for p in q.results())
        assert [setools.PortconRange(45, 45)] == ports

    def test_single_equal(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with single port exact match"""
        q = setools.PortconQuery(compiled_policy, ports=(50, 50))

        ports = sorted(p.ports for p in q.results())
        assert [setools.PortconRange(50, 50)] == ports

    def test_range_equal(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with port range exact match"""
        q = setools.PortconQuery(compiled_policy, ports=(50100, 50110))

        ports = sorted(p.ports for p in q.results())
        assert [setools.PortconRange(50100, 50110)] == ports

    def test_single_subset(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with single port subset"""
        q = setools.PortconQuery(compiled_policy, ports=(50200, 50200), ports_subset=True)

        ports = sorted(p.ports for p in q.results())
        assert [setools.PortconRange(50200, 50200)] == ports

    def test_range_subset(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with range subset"""
        q = setools.PortconQuery(compiled_policy, ports=(50301, 50309), ports_subset=True)

        ports = sorted(p.ports for p in q.results())
        assert [setools.PortconRange(50300, 50310)] == ports

    def test_range_subset_edge1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with range subset, equal edge case"""
        q = setools.PortconQuery(compiled_policy, ports=(50300, 50310), ports_subset=True)

        ports = sorted(p.ports for p in q.results())
        assert [setools.PortconRange(50300, 50310)] == ports

    def test_single_proper_subset(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with single port proper subset"""
        q = setools.PortconQuery(
            compiled_policy, ports=(50400, 50400), ports_subset=True, ports_proper=True)

        ports = sorted(p.ports for p in q.results())
        assert [] == ports

    def test_range_proper_subset(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with range proper subset"""
        q = setools.PortconQuery(
            compiled_policy, ports=(50501, 50509), ports_subset=True, ports_proper=True)

        ports = sorted(p.ports for p in q.results())
        assert [setools.PortconRange(50500, 50510)] == ports

    def test_range_proper_subset_edge1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with range proper subset, equal edge case"""
        q = setools.PortconQuery(
            compiled_policy, ports=(50500, 50510), ports_subset=True, ports_proper=True)

        ports = sorted(p.ports for p in q.results())
        assert [] == ports

    def test_range_proper_subset_edge2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with range proper subset, low equal edge case"""
        q = setools.PortconQuery(
            compiled_policy, ports=(50500, 50509), ports_subset=True, ports_proper=True)

        ports = sorted(p.ports for p in q.results())
        assert [setools.PortconRange(50500, 50510)] == ports

    def test_range_proper_subset_edge3(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with range proper subset, high equal edge case"""
        q = setools.PortconQuery(
            compiled_policy, ports=(50501, 50510), ports_subset=True, ports_proper=True)

        ports = sorted(p.ports for p in q.results())
        assert [setools.PortconRange(50500, 50510)] == ports

    def test_single_superset(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with single port superset"""
        q = setools.PortconQuery(compiled_policy, ports=(50600, 50602), ports_superset=True)

        ports = sorted(p.ports for p in q.results())
        assert [setools.PortconRange(50601, 50601)] == ports

    def test_single_superset_edge1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with single port superset, equal edge case"""
        q = setools.PortconQuery(compiled_policy, ports=(50601, 50601), ports_superset=True)

        ports = sorted(p.ports for p in q.results())
        assert [setools.PortconRange(50601, 50601)] == ports

    def test_range_superset(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with range superset"""
        q = setools.PortconQuery(compiled_policy, ports=(50700, 50711), ports_superset=True)

        ports = sorted(p.ports for p in q.results())
        assert [setools.PortconRange(50700, 50710)] == ports

    def test_range_superset_edge1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with range superset, equal edge case"""
        q = setools.PortconQuery(compiled_policy, ports=(50700, 50710), ports_superset=True)

        ports = sorted(p.ports for p in q.results())
        assert [setools.PortconRange(50700, 50710)] == ports

    def test_single_proper_superset(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with single port proper superset"""
        q = setools.PortconQuery(
            compiled_policy, ports=(50800, 50802), ports_superset=True, ports_proper=True)

        ports = sorted(p.ports for p in q.results())
        assert [setools.PortconRange(50801, 50801)] == ports

    def test_single_proper_superset_edge1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with single port proper superset, equal edge case"""
        q = setools.PortconQuery(
            compiled_policy, ports=(50801, 50801), ports_superset=True, ports_proper=True)

        ports = sorted(p.ports for p in q.results())
        assert [] == ports

    def test_single_proper_superset_edge2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with single port proper superset, low equal edge case"""
        q = setools.PortconQuery(
            compiled_policy, ports=(50801, 50802), ports_superset=True, ports_proper=True)

        ports = sorted(p.ports for p in q.results())
        assert [setools.PortconRange(50801, 50801)] == ports

    def test_single_proper_superset_edge3(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with single port proper superset, high equal edge case"""
        q = setools.PortconQuery(
            compiled_policy, ports=(50800, 50801), ports_superset=True, ports_proper=True)

        ports = sorted(p.ports for p in q.results())
        assert [setools.PortconRange(50801, 50801)] == ports

    def test_range_proper_superset(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with range proper superset"""
        q = setools.PortconQuery(
            compiled_policy, ports=(50900, 50911), ports_superset=True, ports_proper=True)

        ports = sorted(p.ports for p in q.results())
        assert [setools.PortconRange(50901, 50910)] == ports

    def test_range_proper_superset_edge1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with range proper superset, equal edge case"""
        q = setools.PortconQuery(
            compiled_policy, ports=(50901, 50910), ports_superset=True, ports_proper=True)

        ports = sorted(p.ports for p in q.results())
        assert [] == ports

    def test_range_proper_superset_edge2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with range proper superset, equal high port edge case"""
        q = setools.PortconQuery(
            compiled_policy, ports=(50900, 50910), ports_superset=True, ports_proper=True)

        ports = sorted(p.ports for p in q.results())
        assert [setools.PortconRange(50901, 50910)] == ports

    def test_range_proper_superset_edge3(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with range proper superset, equal low port edge case"""
        q = setools.PortconQuery(
            compiled_policy, ports=(50901, 50911), ports_superset=True, ports_proper=True)

        ports = sorted(p.ports for p in q.results())
        assert [setools.PortconRange(50901, 50910)] == ports

    def test_single_overlap(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with single overlap"""
        q = setools.PortconQuery(compiled_policy, ports=(60001, 60001), ports_overlap=True)

        ports = sorted(p.ports for p in q.results())
        assert [setools.PortconRange(60001, 60001)] == ports

    def test_single_overlap_edge1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with single overlap, range match low"""
        q = setools.PortconQuery(compiled_policy, ports=(60001, 60002), ports_overlap=True)

        ports = sorted(p.ports for p in q.results())
        assert [setools.PortconRange(60001, 60001)] == ports

    def test_single_overlap_edge2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with single overlap, range match high"""
        q = setools.PortconQuery(compiled_policy, ports=(60000, 60001), ports_overlap=True)

        ports = sorted(p.ports for p in q.results())
        assert [setools.PortconRange(60001, 60001)] == ports

    def test_single_overlap_edge3(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with single overlap, range match proper superset"""
        q = setools.PortconQuery(compiled_policy, ports=(60000, 60002), ports_overlap=True)

        ports = sorted(p.ports for p in q.results())
        assert [setools.PortconRange(60001, 60001)] == ports

    def test_range_overlap_low_half(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with range overlap, low half match"""
        q = setools.PortconQuery(compiled_policy, ports=(60100, 60105), ports_overlap=True)

        ports = sorted(p.ports for p in q.results())
        assert [setools.PortconRange(60101, 60110)] == ports

    def test_range_overlap_high_half(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with range overlap, high half match"""
        q = setools.PortconQuery(compiled_policy, ports=(60205, 60211), ports_overlap=True)

        ports = sorted(p.ports for p in q.results())
        assert [setools.PortconRange(60200, 60210)] == ports

    def test_range_overlap_middle(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with range overlap, middle match"""
        q = setools.PortconQuery(compiled_policy, ports=(60305, 60308), ports_overlap=True)

        ports = sorted(p.ports for p in q.results())
        assert [setools.PortconRange(60300, 60310)] == ports

    def test_range_overlap_equal(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with range overlap, equal match"""
        q = setools.PortconQuery(compiled_policy, ports=(60400, 60410), ports_overlap=True)

        ports = sorted(p.ports for p in q.results())
        assert [setools.PortconRange(60400, 60410)] == ports

    def test_range_overlap_superset(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Portcon query with range overlap, superset match"""
        q = setools.PortconQuery(compiled_policy, ports=(60500, 60510), ports_overlap=True)

        ports = sorted(p.ports for p in q.results())
        assert [setools.PortconRange(60501, 60509)] == ports
