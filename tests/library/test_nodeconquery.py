# Copyright 2014, Tresys Technology, LLC
# Copyright 2017, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: GPL-2.0-only
#
from socket import AF_INET6
from ipaddress import IPv4Network, IPv6Network

import pytest
import setools


@pytest.mark.obj_args("tests/library/nodeconquery.conf")
class TestNodeconQuery:

    def test_unset(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Nodecon query with no criteria"""
        # query with no parameters gets all nodecons.
        nodecons = sorted(compiled_policy.nodecons())

        q = setools.NodeconQuery(compiled_policy)
        q_nodecons = sorted(q.results())

        assert nodecons == q_nodecons

    def test_ip_version(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Nodecon query with IP version match."""
        q = setools.NodeconQuery(compiled_policy, ip_version=AF_INET6)

        nodecons = sorted(n.network for n in q.results())
        assert [IPv6Network("1100::/16"), IPv6Network("1110::/16")] == nodecons

    def test_user_exact(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Nodecon query with context user exact match"""
        q = setools.NodeconQuery(compiled_policy, user="user20", user_regex=False)

        nodecons = sorted(n.network for n in q.results())
        assert [IPv4Network("10.1.20.1/32")] == nodecons

    def test_user_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Nodecon query with context user regex match"""
        q = setools.NodeconQuery(compiled_policy, user="user21(a|b)", user_regex=True)

        nodecons = sorted(n.network for n in q.results())
        assert [IPv4Network("10.1.21.1/32"), IPv4Network("10.1.21.2/32")] == nodecons

    def test_role_exact(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Nodecon query with context role exact match"""
        q = setools.NodeconQuery(compiled_policy, role="role30_r", role_regex=False)

        nodecons = sorted(n.network for n in q.results())
        assert [IPv4Network("10.1.30.1/32")] == nodecons

    def test_role_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Nodecon query with context role regex match"""
        q = setools.NodeconQuery(compiled_policy, role="role31(a|c)_r", role_regex=True)

        nodecons = sorted(n.network for n in q.results())
        assert [IPv4Network("10.1.31.1/32"), IPv4Network("10.1.31.3/32")] == nodecons

    def test_type_exact(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Nodecon query with context type exact match"""
        q = setools.NodeconQuery(compiled_policy, type_="type40", type_regex=False)

        nodecons = sorted(n.network for n in q.results())
        assert [IPv4Network("10.1.40.1/32")] == nodecons

    def test_type_regex(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Nodecon query with context type regex match"""
        q = setools.NodeconQuery(compiled_policy, type_="type41(b|c)", type_regex=True)

        nodecons = sorted(n.network for n in q.results())
        assert [IPv4Network("10.1.41.2/32"), IPv4Network("10.1.41.3/32")] == nodecons

    def test_range_exact(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Nodecon query with context range exact match"""
        q = setools.NodeconQuery(compiled_policy, range_="s0:c1 - s0:c0.c4")

        nodecons = sorted(n.network for n in q.results())
        assert [IPv4Network("10.1.50.1/32")] == nodecons

    def test_range_overlap1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Nodecon query with context range overlap match (equal)"""
        q = setools.NodeconQuery(compiled_policy, range_="s1:c1 - s1:c0.c4", range_overlap=True)

        nodecons = sorted(n.network for n in q.results())
        assert [IPv4Network("10.1.51.1/32")] == nodecons

    def test_range_overlap2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Nodecon query with context range overlap match (subset)"""
        q = setools.NodeconQuery(compiled_policy, range_="s1:c1,c2 - s1:c0.c3", range_overlap=True)

        nodecons = sorted(n.network for n in q.results())
        assert [IPv4Network("10.1.51.1/32")] == nodecons

    def test_range_overlap3(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Nodecon query with context range overlap match (superset)"""
        q = setools.NodeconQuery(compiled_policy, range_="s1 - s1:c0.c4", range_overlap=True)

        nodecons = sorted(n.network for n in q.results())
        assert [IPv4Network("10.1.51.1/32")] == nodecons

    def test_range_overlap4(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Nodecon query with context range overlap match (overlap low level)"""
        q = setools.NodeconQuery(compiled_policy, range_="s1 - s1:c1,c2", range_overlap=True)

        nodecons = sorted(n.network for n in q.results())
        assert [IPv4Network("10.1.51.1/32")] == nodecons

    def test_range_overlap5(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Nodecon query with context range overlap match (overlap high level)"""
        q = setools.NodeconQuery(compiled_policy, range_="s1:c1,c2 - s1:c0.c4", range_overlap=True)

        nodecons = sorted(n.network for n in q.results())
        assert [IPv4Network("10.1.51.1/32")] == nodecons

    def test_range_subset1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Nodecon query with context range subset match"""
        q = setools.NodeconQuery(compiled_policy, range_="s2:c1,c2 - s2:c0.c3", range_overlap=True)

        nodecons = sorted(n.network for n in q.results())
        assert [IPv4Network("10.1.52.1/32")] == nodecons

    def test_range_subset2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Nodecon query with context range subset match (equal)"""
        q = setools.NodeconQuery(compiled_policy, range_="s2:c1 - s2:c1.c3", range_overlap=True)

        nodecons = sorted(n.network for n in q.results())
        assert [IPv4Network("10.1.52.1/32")] == nodecons

    def test_range_superset1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Nodecon query with context range superset match"""
        q = setools.NodeconQuery(compiled_policy, range_="s3 - s3:c0.c4", range_superset=True)

        nodecons = sorted(n.network for n in q.results())
        assert [IPv4Network("10.1.53.1/32")] == nodecons

    def test_range_superset2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Nodecon query with context range superset match (equal)"""
        q = setools.NodeconQuery(compiled_policy, range_="s3:c1 - s3:c1.c3", range_superset=True)

        nodecons = sorted(n.network for n in q.results())
        assert [IPv4Network("10.1.53.1/32")] == nodecons

    def test_range_proper_subset1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Nodecon query with context range proper subset match"""
        q = setools.NodeconQuery(compiled_policy, range_="s4:c1,c2", range_subset=True,
                                 range_proper=True)

        nodecons = sorted(n.network for n in q.results())
        assert [IPv4Network("10.1.54.1/32")] == nodecons

    def test_range_proper_subset2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Nodecon query with context range proper subset match (equal)"""
        q = setools.NodeconQuery(compiled_policy, range_="s4:c1 - s4:c1.c3", range_subset=True,
                                 range_proper=True)

        nodecons = sorted(n.network for n in q.results())
        assert [] == nodecons

    def test_range_proper_subset3(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Nodecon query with context range proper subset match (equal low only)"""
        q = setools.NodeconQuery(compiled_policy, range_="s4:c1 - s4:c1.c2", range_subset=True,
                                 range_proper=True)

        nodecons = sorted(n.network for n in q.results())
        assert [IPv4Network("10.1.54.1/32")] == nodecons

    def test_range_proper_subset4(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Nodecon query with context range proper subset match (equal high only)"""
        q = setools.NodeconQuery(compiled_policy, range_="s4:c1,c2 - s4:c1.c3", range_subset=True,
                                 range_proper=True)

        nodecons = sorted(n.network for n in q.results())
        assert [IPv4Network("10.1.54.1/32")] == nodecons

    def test_range_proper_superset1(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Nodecon query with context range proper superset match"""
        q = setools.NodeconQuery(compiled_policy, range_="s5 - s5:c0.c4", range_superset=True,
                                 range_proper=True)

        nodecons = sorted(n.network for n in q.results())
        assert [IPv4Network("10.1.55.1/32")] == nodecons

    def test_range_proper_superset2(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Nodecon query with context range proper superset match (equal)"""
        q = setools.NodeconQuery(compiled_policy, range_="s5:c1 - s5:c1.c3", range_superset=True,
                                 range_proper=True)

        nodecons = sorted(n.network for n in q.results())
        assert [] == nodecons

    def test_range_proper_superset3(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Nodecon query with context range proper superset match (equal low)"""
        q = setools.NodeconQuery(compiled_policy, range_="s5:c1 - s5:c1.c4", range_superset=True,
                                 range_proper=True)

        nodecons = sorted(n.network for n in q.results())
        assert [IPv4Network("10.1.55.1/32")] == nodecons

    def test_range_proper_superset4(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Nodecon query with context range proper superset match (equal high)"""
        q = setools.NodeconQuery(compiled_policy, range_="s5 - s5:c1.c3", range_superset=True,
                                 range_proper=True)

        nodecons = sorted(n.network for n in q.results())
        assert [IPv4Network("10.1.55.1/32")] == nodecons

    def test_v4network_equal(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Nodecon query with IPv4 equal network"""
        q = setools.NodeconQuery(compiled_policy, network="192.168.1.0/24", network_overlap=False)

        nodecons = sorted(n.network for n in q.results())
        assert [IPv4Network("192.168.1.0/24")] == nodecons

    def test_v4network_overlap(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Nodecon query with IPv4 network overlap"""
        q = setools.NodeconQuery(compiled_policy, network="192.168.201.0/24", network_overlap=True)

        nodecons = sorted(n.network for n in q.results())
        assert [IPv4Network("192.168.200.0/22")] == nodecons

    def test_v6network_equal(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Nodecon query with IPv6 equal network"""
        q = setools.NodeconQuery(compiled_policy, network="1100::/16", network_overlap=False)

        nodecons = sorted(n.network for n in q.results())
        assert [IPv6Network("1100::/16")] == nodecons

    def test_v6network_overlap(self, compiled_policy: setools.SELinuxPolicy) -> None:
        """Nodecon query with IPv6 network overlap"""
        q = setools.NodeconQuery(compiled_policy, network="1110:8000::/17", network_overlap=True)

        nodecons = sorted(n.network for n in q.results())
        assert [IPv6Network("1110::/16")] == nodecons
