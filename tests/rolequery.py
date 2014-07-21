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
from libapol.rolequery import RoleQuery


class RoleQueryTest(unittest.TestCase):

    def setUp(self):
        self.p = SELinuxPolicy("tests/rolequery.conf")

    def test_000_unset(self):
        """Role query with no criteria."""
        # query with no parameters gets all types.
        for numroles, r in enumerate(self.p.roles(), start=1):
            pass

        q = RoleQuery(self.p)
        for q_numroles, t in enumerate(q.results(), start=1):
            pass

        # numroles-1 as object_r is skipped from the role query
        self.assertEqual(numroles-1, q_numroles)

    def test_001_name_exact(self):
        """Role query with exact name match."""
        q = RoleQuery(self.p, name="test1")

        # manually consume the generator:
        r = sorted(q.results())
        self.assertEqual(len(r), 1)

        self.assertEqual(r[0], "test1")

    def test_002_name_regex(self):
        """Role query with regex name match."""
        q = RoleQuery(self.p, name="test2(a|b)", name_regex=True)

        # manually consume the generator:
        r = sorted(q.results())
        self.assertEqual(len(r), 2)

        self.assertEqual(r[0], "test2a")
        self.assertEqual(r[1], "test2b")

    def test_010_type_intersect(self):
        """Role query with type set intersection."""
        q = RoleQuery(self.p, types=["test10a", "test10b"])

        # manually consume the generator:
        r = sorted(q.results())
        self.assertEqual(len(r), 6)

        self.assertEqual(r[0], "test10r1")
        self.assertEqual(r[1], "test10r2")
        self.assertEqual(r[2], "test10r3")
        self.assertEqual(r[3], "test10r4")
        self.assertEqual(r[4], "test10r5")
        self.assertEqual(r[5], "test10r6")

    def test_011_type_equality(self):
        """Role query with type set equality."""
        q = RoleQuery(self.p, types=["test11a", "test11b"], types_equal=True)

        # manually consume the generator:
        r = sorted(q.results())
        self.assertEqual(len(r), 1)

        self.assertEqual(r[0], "test11r2")

    def test_012_type_regex(self):
        """Role query with type set match."""
        q = RoleQuery(self.p, types="test12(a|b)", types_regex=True)

        # manually consume the generator:
        r = sorted(q.results())
        self.assertEqual(len(r), 6)

        self.assertEqual(r[0], "test12r1")
        self.assertEqual(r[1], "test12r2")
        self.assertEqual(r[2], "test12r3")
        self.assertEqual(r[3], "test12r4")
        self.assertEqual(r[4], "test12r5")
        self.assertEqual(r[5], "test12r6")
