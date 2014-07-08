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
from libapol.polcapquery import PolCapQuery


class PolCapQueryTest(unittest.TestCase):

    def setUp(self):
        self.p = SELinuxPolicy("tests/polcapquery.conf")

    def test_000_unset(self):
        """Policy capability query with no criteria"""
        # query with no parameters gets all capabilities.
        for numcaps, c in enumerate(self.p.polcaps(), start=1):
            pass

        q = PolCapQuery(self.p)
        for q_numcaps, c in enumerate(q.results(), start=1):
            pass

        self.assertEqual(numcaps, q_numcaps)

    def test_001_name_exact(self):
        """Policy capability query with exact match"""
        q = PolCapQuery(self.p, name="open_perms", name_regex=False)

        # manually consume the generator:
        caps = q.results()
        c = caps.next()

        self.assertEqual(c, "open_perms")

        self.assertRaises(StopIteration, caps.next)

    def test_002_name_regex(self):
        """Policy capability query with regex match"""

        q = PolCapQuery(self.p, name="pe?er", name_regex=True)

        # manually consume the generator:
        c = sorted(q.results())
        self.assertEqual(len(c), 2)

        self.assertEqual(c[0], "network_peer_controls")
        self.assertEqual(c[1], "open_perms")
