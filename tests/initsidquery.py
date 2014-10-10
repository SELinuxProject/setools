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

from libapol import SELinuxPolicy
from libapol.initsidquery import InitialSIDQuery


class InitialSIDQueryTest(unittest.TestCase):

    def setUp(self):
        self.p = SELinuxPolicy("tests/initsidquery.conf")

    def test_000_unset(self):
        """Initial SID query with no criteria"""
        # query with no parameters gets all SIDs.
        for numrules, s in enumerate(self.p.initialsids(), start=1):
            pass

        q = InitialSIDQuery(self.p)
        for q_numrules, s in enumerate(q.results(), start=1):
            pass

        self.assertEqual(numrules, q_numrules)

    def test_001_name_exact(self):
        """Initial SID query with exact match"""
        q = InitialSIDQuery(self.p, name="test1", name_regex=False)

        sids = sorted(str(s) for s in q.results())
        self.assertListEqual(["test1"], sids)

    def test_002_name_regex(self):
        """Initial SID query with regex match"""
        q = InitialSIDQuery(self.p, name="test2(a|b)", name_regex=True)

        sids = sorted(str(s) for s in q.results())
        self.assertListEqual(["test2a", "test2b"], sids)

    def test_010_user_exact(self):
        """Initial SID query with context user exact match"""
        q = InitialSIDQuery(self.p, user="user10", user_regex=False)

        sids = sorted(str(s) for s in q.results())
        self.assertListEqual(["test10"], sids)

    def test_011_user_regex(self):
        """Initial SID query with context user regex match"""
        q = InitialSIDQuery(self.p, user="user11(a|b)", user_regex=True)

        sids = sorted(str(s) for s in q.results())
        self.assertListEqual(["test11a", "test11b"], sids)

    def test_020_role_exact(self):
        """Initial SID query with context role exact match"""
        q = InitialSIDQuery(self.p, role="role20_r", role_regex=False)

        sids = sorted(str(s) for s in q.results())
        self.assertListEqual(["test20"], sids)

    def test_021_role_regex(self):
        """Initial SID query with context role regex match"""
        q = InitialSIDQuery(self.p, role="role21(a|c)_r", role_regex=True)

        sids = sorted(str(s) for s in q.results())
        self.assertListEqual(["test21a", "test21c"], sids)

    def test_030_type_exact(self):
        """Initial SID query with context type exact match"""
        q = InitialSIDQuery(self.p, type_="type30", type_regex=False)

        sids = sorted(str(s) for s in q.results())
        self.assertListEqual(["test30"], sids)

    def test_031_type_regex(self):
        """Initial SID query with context type regex match"""
        q = InitialSIDQuery(self.p, type_="type31(b|c)", type_regex=True)

        sids = sorted(str(s) for s in q.results())
        self.assertListEqual(["test31b", "test31c"], sids)
