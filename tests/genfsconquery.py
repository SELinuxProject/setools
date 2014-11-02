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
from setools.genfsconquery import GenfsconQuery


class GenfsconQueryTest(unittest.TestCase):

    def setUp(self):
        self.p = SELinuxPolicy("tests/genfsconquery.conf")

    def test_000_unset(self):
        """Genfscon query with no criteria"""
        # query with no parameters gets all genfs.
        for numrules, s in enumerate(self.p.genfscons(), start=1):
            pass

        q = GenfsconQuery(self.p)
        for q_numrules, s in enumerate(q.results(), start=1):
            pass

        self.assertEqual(numrules, q_numrules)

    def test_001_fs_exact(self):
        """Genfscon query with exact fs match"""
        q = GenfsconQuery(self.p, fs="test1", fs_regex=False)

        genfs = sorted(s.fs for s in q.results())
        self.assertListEqual(["test1"], genfs)

    def test_002_fs_regex(self):
        """Genfscon query with regex fs match"""
        q = GenfsconQuery(self.p, fs="test2(a|b)", fs_regex=True)

        genfs = sorted(s.fs for s in q.results())
        self.assertListEqual(["test2a", "test2b"], genfs)

    def test_010_path_exact(self):
        """Genfscon query with exact path match"""
        q = GenfsconQuery(self.p, path="/sys", path_regex=False)

        genfs = sorted(s.fs for s in q.results())
        self.assertListEqual(["test10"], genfs)

    def test_011_path_regex(self):
        """Genfscon query with regex path match"""
        q = GenfsconQuery(self.p, path="/(spam|eggs)", path_regex=True)

        genfs = sorted(s.fs for s in q.results())
        self.assertListEqual(["test11a", "test11b"], genfs)

    def test_020_user_exact(self):
        """Genfscon query with context user exact match"""
        q = GenfsconQuery(self.p, user="user20", user_regex=False)

        genfs = sorted(s.fs for s in q.results())
        self.assertListEqual(["test20"], genfs)

    def test_021_user_regex(self):
        """Genfscon query with context user regex match"""
        q = GenfsconQuery(self.p, user="user21(a|b)", user_regex=True)

        genfs = sorted(s.fs for s in q.results())
        self.assertListEqual(["test21a", "test21b"], genfs)

    def test_030_role_exact(self):
        """Genfscon query with context role exact match"""
        q = GenfsconQuery(self.p, role="role30_r", role_regex=False)

        genfs = sorted(s.fs for s in q.results())
        self.assertListEqual(["test30"], genfs)

    def test_031_role_regex(self):
        """Genfscon query with context role regex match"""
        q = GenfsconQuery(self.p, role="role31(a|c)_r", role_regex=True)

        genfs = sorted(s.fs for s in q.results())
        self.assertListEqual(["test31a", "test31c"], genfs)

    def test_040_type_exact(self):
        """Genfscon query with context type exact match"""
        q = GenfsconQuery(self.p, type_="type40", type_regex=False)

        genfs = sorted(s.fs for s in q.results())
        self.assertListEqual(["test40"], genfs)

    def test_041_type_regex(self):
        """Genfscon query with context type regex match"""
        q = GenfsconQuery(self.p, type_="type41(b|c)", type_regex=True)

        genfs = sorted(s.fs for s in q.results())
        self.assertListEqual(["test41b", "test41c"], genfs)
