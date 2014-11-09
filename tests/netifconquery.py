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
import unittest

from setools import SELinuxPolicy
from setools.netifconquery import NetifconQuery


class NetifconQueryTest(unittest.TestCase):

    def setUp(self):
        self.p = SELinuxPolicy("tests/netifconquery.conf")

    def test_000_unset(self):
        """Netifcon query with no criteria"""
        # query with no parameters gets all netifs.
        for numrules, s in enumerate(self.p.netifcons(), start=1):
            pass

        q = NetifconQuery(self.p)
        for q_numrules, s in enumerate(q.results(), start=1):
            pass

        self.assertEqual(numrules, q_numrules)

    def test_001_name_exact(self):
        """Netifcon query with exact match"""
        q = NetifconQuery(self.p, name="test1", name_regex=False)

        netifs = sorted(s.netif for s in q.results())
        self.assertListEqual(["test1"], netifs)

    def test_002_name_regex(self):
        """Netifcon query with regex match"""
        q = NetifconQuery(self.p, name="test2(a|b)", name_regex=True)

        netifs = sorted(s.netif for s in q.results())
        self.assertListEqual(["test2a", "test2b"], netifs)

    def test_010_user_exact(self):
        """Netifcon query with context user exact match"""
        q = NetifconQuery(self.p, user="user10", user_regex=False)

        netifs = sorted(s.netif for s in q.results())
        self.assertListEqual(["test10"], netifs)

    def test_011_user_regex(self):
        """Netifcon query with context user regex match"""
        q = NetifconQuery(self.p, user="user11(a|b)", user_regex=True)

        netifs = sorted(s.netif for s in q.results())
        self.assertListEqual(["test11a", "test11b"], netifs)

    def test_020_role_exact(self):
        """Netifcon query with context role exact match"""
        q = NetifconQuery(self.p, role="role20_r", role_regex=False)

        netifs = sorted(s.netif for s in q.results())
        self.assertListEqual(["test20"], netifs)

    def test_021_role_regex(self):
        """Netifcon query with context role regex match"""
        q = NetifconQuery(self.p, role="role21(a|c)_r", role_regex=True)

        netifs = sorted(s.netif for s in q.results())
        self.assertListEqual(["test21a", "test21c"], netifs)

    def test_030_type_exact(self):
        """Netifcon query with context type exact match"""
        q = NetifconQuery(self.p, type_="type30", type_regex=False)

        netifs = sorted(s.netif for s in q.results())
        self.assertListEqual(["test30"], netifs)

    def test_031_type_regex(self):
        """Netifcon query with context type regex match"""
        q = NetifconQuery(self.p, type_="type31(b|c)", type_regex=True)

        netifs = sorted(s.netif for s in q.results())
        self.assertListEqual(["test31b", "test31c"], netifs)
