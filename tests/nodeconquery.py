# Copyright 2014, Tresys Technology, LLC
#
# This file is part of SETools.
#
# SETools is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# SETools is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with SETools.  If not, see <http://www.gnu.org/licenses/>.
#
import sys
import unittest
from socket import AF_INET6

from setools import SELinuxPolicy
from setools.nodeconquery import NodeconQuery


class NodeconQueryTest(unittest.TestCase):

    def setUp(self):
        self.p = SELinuxPolicy("tests/nodeconquery.conf")

    def test_000_unset(self):
        """Nodecon query with no criteria"""
        # query with no parameters gets all nodecons.
        for numrules, s in enumerate(self.p.nodecons(), start=1):
            pass

        q = NodeconQuery(self.p)
        for q_numrules, s in enumerate(q.results(), start=1):
            pass

        self.assertEqual(numrules, q_numrules)

    def test_001_ip_version(self):
        """Nodecon query with IP version match."""
        q = NodeconQuery(self.p, version=AF_INET6)

        nodecons = sorted(n.address for n in q.results())
        self.assertListEqual(["1100::", "1110::"], nodecons)

    def test_020_user_exact(self):
        """Nodecon query with context user exact match"""
        q = NodeconQuery(self.p, user="user20", user_regex=False)

        nodecons = sorted(n.address for n in q.results())
        self.assertListEqual(["10.1.20.1"], nodecons)

    def test_021_user_regex(self):
        """Nodecon query with context user regex match"""
        q = NodeconQuery(self.p, user="user21(a|b)", user_regex=True)

        nodecons = sorted(n.address for n in q.results())
        self.assertListEqual(["10.1.21.1", "10.1.21.2"], nodecons)

    def test_030_role_exact(self):
        """Nodecon query with context role exact match"""
        q = NodeconQuery(self.p, role="role30_r", role_regex=False)

        nodecons = sorted(n.address for n in q.results())
        self.assertListEqual(["10.1.30.1"], nodecons)

    def test_031_role_regex(self):
        """Nodecon query with context role regex match"""
        q = NodeconQuery(self.p, role="role31(a|c)_r", role_regex=True)

        nodecons = sorted(n.address for n in q.results())
        self.assertListEqual(["10.1.31.1", "10.1.31.3"], nodecons)

    def test_040_type_exact(self):
        """Nodecon query with context type exact match"""
        q = NodeconQuery(self.p, type_="type40", type_regex=False)

        nodecons = sorted(n.address for n in q.results())
        self.assertListEqual(["10.1.40.1"], nodecons)

    def test_041_type_regex(self):
        """Nodecon query with context type regex match"""
        q = NodeconQuery(self.p, type_="type41(b|c)", type_regex=True)

        nodecons = sorted(n.address for n in q.results())
        self.assertListEqual(["10.1.41.2", "10.1.41.3"], nodecons)

    def test_100_v4network_equal(self):
        """Nodecon query with IPv4 equal network"""
        if sys.version_info < (3, 3):
            self.assertRaises(
                RuntimeError, NodeconQuery, self.p, net="10.1.100.0/24", net_overlap=False)
        else:
            q = NodeconQuery(self.p, net="10.1.100.0/24", net_overlap=False)

            nodecons = sorted(n.address for n in q.results())
            self.assertListEqual(["10.1.100.0"], nodecons)

    def test_101_v4network_overlap(self):
        """Nodecon query with IPv4 network overlap"""
        if sys.version_info < (3, 3):
            self.assertRaises(
                RuntimeError, NodeconQuery, self.p, net="10.1.101.128/25", net_overlap=True)
        else:
            q = NodeconQuery(self.p, net="10.1.101.128/25", net_overlap=True)

            nodecons = sorted(n.address for n in q.results())
            self.assertListEqual(["10.1.101.0"], nodecons)

    def test_110_v6network_equal(self):
        """Nodecon query with IPv6 equal network"""
        if sys.version_info < (3, 3):
            self.assertRaises(
                RuntimeError, NodeconQuery, self.p, net="1100::/16", net_overlap=False)
        else:
            q = NodeconQuery(self.p, net="1100::/16", net_overlap=False)

            nodecons = sorted(n.address for n in q.results())
            self.assertListEqual(["1100::"], nodecons)

    def test_111_v6network_overlap(self):
        """Nodecon query with IPv6 network overlap"""
        if sys.version_info < (3, 3):
            self.assertRaises(
                RuntimeError, NodeconQuery, self.p, net="1110:8000::/17", net_overlap=True)
        else:
            q = NodeconQuery(self.p, net="1110:8000::/17", net_overlap=True)

            nodecons = sorted(n.address for n in q.results())
            self.assertListEqual(["1110::"], nodecons)
