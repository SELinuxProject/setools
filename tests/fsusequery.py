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
from setools.fsusequery import FSUseQuery


class FSUseQueryTest(unittest.TestCase):

    def setUp(self):
        self.p = SELinuxPolicy("tests/fsusequery.conf")

    def test_000_unset(self):
        """fs_use_* query with no criteria"""
        # query with no parameters gets all fs_use_*.
        for numrules, s in enumerate(self.p.fs_uses(), start=1):
            pass

        q = FSUseQuery(self.p)
        for q_numrules, s in enumerate(q.results(), start=1):
            pass

        self.assertEqual(numrules, q_numrules)

    def test_001_fs_exact(self):
        """fs_use_* query with exact fs match"""
        q = FSUseQuery(self.p, fs="test1", fs_regex=False)

        fsu = sorted(s.fs for s in q.results())
        self.assertListEqual(["test1"], fsu)

    def test_002_fs_regex(self):
        """fs_use_* query with regex fs match"""
        q = FSUseQuery(self.p, fs="test2(a|b)", fs_regex=True)

        fsu = sorted(s.fs for s in q.results())
        self.assertListEqual(["test2a", "test2b"], fsu)

    def test_010_ruletype(self):
        """fs_use_* query with ruletype match"""
        q = FSUseQuery(self.p, ruletype=['fs_use_trans', 'fs_use_task'])

        fsu = sorted(s.fs for s in q.results())
        self.assertListEqual(["test10a", "test10b"], fsu)

    def test_020_user_exact(self):
        """fs_use_* query with context user exact match"""
        q = FSUseQuery(self.p, user="user20", user_regex=False)

        fsu = sorted(s.fs for s in q.results())
        self.assertListEqual(["test20"], fsu)

    def test_021_user_regex(self):
        """fs_use_* query with context user regex match"""
        q = FSUseQuery(self.p, user="user21(a|b)", user_regex=True)

        fsu = sorted(s.fs for s in q.results())
        self.assertListEqual(["test21a", "test21b"], fsu)

    def test_030_role_exact(self):
        """fs_use_* query with context role exact match"""
        q = FSUseQuery(self.p, role="role30_r", role_regex=False)

        fsu = sorted(s.fs for s in q.results())
        self.assertListEqual(["test30"], fsu)

    def test_031_role_regex(self):
        """fs_use_* query with context role regex match"""
        q = FSUseQuery(self.p, role="role31(a|c)_r", role_regex=True)

        fsu = sorted(s.fs for s in q.results())
        self.assertListEqual(["test31a", "test31c"], fsu)

    def test_040_type_exact(self):
        """fs_use_* query with context type exact match"""
        q = FSUseQuery(self.p, type_="type40", type_regex=False)

        fsu = sorted(s.fs for s in q.results())
        self.assertListEqual(["test40"], fsu)

    def test_041_type_regex(self):
        """fs_use_* query with context type regex match"""
        q = FSUseQuery(self.p, type_="type41(b|c)", type_regex=True)

        fsu = sorted(s.fs for s in q.results())
        self.assertListEqual(["test41b", "test41c"], fsu)
