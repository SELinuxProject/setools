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
from libapol.boolquery import BoolQuery


class BoolQueryTest(unittest.TestCase):

    def setUp(self):
        self.p = SELinuxPolicy("tests/boolquery.conf")

    def test_000_unset(self):
        """Boolean query with no criteria."""
        # query with no parameters gets all Booleans.
        for numbools, b in enumerate(self.p.bools(), start=1):
            pass

        q = BoolQuery(self.p)
        for q_numbools, b in enumerate(q.results(), start=1):
            pass

        self.assertEqual(numbools, q_numbools)

    def test_001_name_exact(self):
        """Boolean query with exact match"""
        q = BoolQuery(self.p, name="test1")

        # manually consume the generator:
        bools = q.results()
        b = bools.next()

        self.assertEqual(b, "test1")

        self.assertRaises(StopIteration, bools.next)

    def test_002_name_regex(self):
        """Boolean query with regex match."""
        q = BoolQuery(self.p, name="test2(a|b)", name_regex=True)

        # manually consume the generator:
        b = sorted(q.results())
        self.assertEqual(len(b), 2)

        self.assertEqual(b[0], "test2a")
        self.assertEqual(b[1], "test2b")

    def test_010_default(self):
        """Boolean query with default state match."""
        q = BoolQuery(self.p, match_default=True, default=False)

        # manually consume the generator:
        b = sorted(q.results())
        self.assertEqual(len(b), 2)

        self.assertEqual(b[0], "test10a")
        self.assertEqual(b[1], "test10b")
