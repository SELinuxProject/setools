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
from setools.userquery import UserQuery


class UserQueryTest(unittest.TestCase):

    def setUp(self):
        self.p = SELinuxPolicy("tests/userquery.conf")

    def test_000_unset(self):
        """User query with no criteria."""
        # query with no parameters gets all types.
        allusers = sorted(self.p.users())

        q = UserQuery(self.p)
        qusers = sorted(q.results())

        self.assertListEqual(allusers, qusers)

    def test_001_name_exact(self):
        """User query with exact name match."""
        q = UserQuery(self.p, name="test1_u")

        users = sorted(str(u) for u in q.results())
        self.assertListEqual(["test1_u"], users)

    def test_002_name_regex(self):
        """User query with regex name match."""
        q = UserQuery(self.p, name="test2_u(1|2)", name_regex=True)

        users = sorted(str(u) for u in q.results())
        self.assertListEqual(["test2_u1", "test2_u2"], users)

    def test_010_role_intersect(self):
        """User query with role set intersection."""
        q = UserQuery(self.p, roles=["test10a_r", "test10b_r"])

        users = sorted(str(u) for u in q.results())
        self.assertListEqual(["test10_u1", "test10_u2", "test10_u3",
                              "test10_u4", "test10_u5", "test10_u6"], users)

    def test_011_role_equality(self):
        """User query with role set equality."""
        q = UserQuery(
            self.p, roles=["test11a_r", "test11b_r"], roles_equal=True)

        users = sorted(str(u) for u in q.results())
        self.assertListEqual(["test11_u2"], users)

    def test_012_role_regex(self):
        """User query with role regex match."""
        q = UserQuery(self.p, roles="test12(a|b)_r", roles_regex=True)

        users = sorted(str(u) for u in q.results())
        self.assertListEqual(["test12_u1", "test12_u2", "test12_u3",
                              "test12_u4", "test12_u5", "test12_u6"], users)
