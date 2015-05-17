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

from setools import SELinuxPolicy, BoolQuery


class BoolQueryTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.p = SELinuxPolicy("tests/boolquery.conf")

    def test_000_unset(self):
        """Boolean query with no criteria."""
        # query with no parameters gets all Booleans.
        allbools = sorted(str(b) for b in self.p.bools())

        q = BoolQuery(self.p)
        qbools = sorted(str(b) for b in q.results())

        self.assertListEqual(allbools, qbools)

    def test_001_name_exact(self):
        """Boolean query with exact match"""
        q = BoolQuery(self.p, name="test1")

        bools = sorted(str(b) for b in q.results())
        self.assertListEqual(["test1"], bools)

    def test_002_name_regex(self):
        """Boolean query with regex match."""
        q = BoolQuery(self.p, name="test2(a|b)", name_regex=True)

        bools = sorted(str(b) for b in q.results())
        self.assertListEqual(["test2a", "test2b"], bools)

    def test_010_default(self):
        """Boolean query with default state match."""
        q = BoolQuery(self.p, default=False)

        bools = sorted(str(b) for b in q.results())
        self.assertListEqual(["test10a", "test10b"], bools)
