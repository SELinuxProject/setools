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
from libapol.permissivequery import PermissiveQuery


class PolCapQueryTest(unittest.TestCase):

    def setUp(self):
        self.p = SELinuxPolicy("tests/permissivequery.conf")

    def test_000_unset(self):
        """Policy capability query with no criteria"""
        # query with no parameters gets all permissives
        for numtypes, t in enumerate(self.p.permissives(), start=1):
            pass

        q = PermissiveQuery(self.p)
        for q_numtypes, t in enumerate(q.results(), start=1):
            pass

        self.assertEqual(numtypes, q_numtypes)

    def test_001_name_exact(self):
        """Permissive query with exact match"""
        q = PermissiveQuery(self.p, name="test1", name_regex=False)

        types = sorted(str(t) for t in q.results())
        self.assertListEqual(["test1"], types)

    def test_002_name_regex(self):
        """Permissive query query with regex match"""
        q = PermissiveQuery(self.p, name="test2(a|b)$", name_regex=True)

        types = sorted(str(t) for t in q.results())
        self.assertListEqual(["test2a", "test2b"], types)
