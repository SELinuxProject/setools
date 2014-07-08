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
from libapol.typequery import TypeQuery


class TypeQueryTest(unittest.TestCase):

    def setUp(self):
        self.p = SELinuxPolicy("tests/typequery.conf")

    def test_000_unset(self):
        """Type query with no criteria."""
        # query with no parameters gets all types.
        for numtypes, t in enumerate(self.p.types(), start=1):
            pass

        q = TypeQuery(self.p)
        for q_numtypes, t in enumerate(q.results(), start=1):
            pass

        self.assertEqual(numtypes, q_numtypes)

    def test_001_name_exact(self):
        """Type query with exact name match."""
        q = TypeQuery(self.p, name="test1")

        # manually consume the generator:
        types = q.results()
        t = types.next()

        self.assertEqual(t, "test1")

        self.assertRaises(StopIteration, types.next)

    def test_002_name_regex(self):
        """Type query with regex name match."""
        q = TypeQuery(self.p, name="test2(a|b)", name_regex=True)

        # manually consume the generator:
        t = sorted(q.results())
        self.assertEqual(len(t), 2)

        self.assertEqual(t[0], "test2a")
        self.assertEqual(t[1], "test2b")

    def test_010_attr_intersect(self):
        """Type query with attribute set intersection."""
        q = TypeQuery(self.p, attrs=["test10a", "test10b"])

        # manually consume the generator:
        t = sorted(q.results())
        self.assertEqual(len(t), 6)

        self.assertEqual(t[0], "test10t1")
        self.assertEqual(t[1], "test10t2")
        self.assertEqual(t[2], "test10t3")
        self.assertEqual(t[3], "test10t4")
        self.assertEqual(t[4], "test10t5")
        self.assertEqual(t[5], "test10t6")

    def test_011_attr_equality(self):
        """Type query with attribute set equality."""
        q = TypeQuery(self.p, attrs=["test11a", "test11b"], attrs_equal=True)

        # manually consume the generator:
        types = q.results()
        t = types.next()

        self.assertEqual(t, "test11t2")

        self.assertRaises(StopIteration, types.next)

    def test_012_attr_regex(self):
        """Type query with attribute regex match."""
        q = TypeQuery(self.p, attrs="test12(a|b)", attrs_regex=True)

        # manually consume the generator:
        t = sorted(q.results())
        self.assertEqual(len(t), 6)

        self.assertEqual(t[0], "test12t1")
        self.assertEqual(t[1], "test12t2")
        self.assertEqual(t[2], "test12t3")
        self.assertEqual(t[3], "test12t4")
        self.assertEqual(t[4], "test12t5")
        self.assertEqual(t[5], "test12t6")

    def test_020_alias_exact(self):
        """Type query with exact alias match."""
        q = TypeQuery(self.p, alias="test20a")

        # manually consume the generator:
        types = q.results()
        t = types.next()

        self.assertEqual(t, "test20t1")

        self.assertRaises(StopIteration, types.next)

    def test_021_alias_regex(self):
        """Type query with regex alias match."""
        q = TypeQuery(self.p, alias="test21(a|b)", alias_regex=True)

        # manually consume the generator:
        t = sorted(q.results())
        self.assertEqual(len(t), 2)

        self.assertEqual(t[0], "test21t1")
        self.assertEqual(t[1], "test21t2")
