# Copyright 2016, Tresys Technology, LLC
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

from setools import SELinuxPolicy, DefaultQuery
from setools.policyrep.exception import InvalidDefaultType, InvalidClass, \
                                        InvalidDefaultValue, InvalidDefaultRange


class DefaultQueryTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.p = SELinuxPolicy("tests/defaultquery.conf")

    def test_000_unset(self):
        """Default query: no criteria."""
        # query with no parameters gets all defaults
        alldefaults = sorted(self.p.defaults())

        q = DefaultQuery(self.p)
        qdefaults = sorted(q.results())

        self.assertListEqual(alldefaults, qdefaults)

    def test_001_ruletype(self):
        """Default query: ruletype criterion."""
        q = DefaultQuery(self.p, ruletype=["default_user"])
        defaults = list(q.results())
        self.assertEqual(1, len(defaults))

        d = defaults[0]
        self.assertEqual("default_user", d.ruletype)
        self.assertEqual("infoflow", d.tclass)
        self.assertEqual("target", d.default)

    def test_010_class_list(self):
        """Default query: object class list match."""
        q = DefaultQuery(self.p, tclass=["infoflow3", "infoflow4"])

        defaults = sorted(d.tclass for d in q.results())
        self.assertListEqual(["infoflow3", "infoflow4"], defaults)

    def test_011_class_regex(self):
        """Default query: object class regex match."""
        q = DefaultQuery(self.p, tclass="infoflow(3|5)", tclass_regex=True)

        defaults = sorted(c.tclass for c in q.results())
        self.assertListEqual(["infoflow3", "infoflow5"], defaults)

    def test_020_default(self):
        """Default query: default setting."""
        q = DefaultQuery(self.p, default="source")

        defaults = sorted(c.tclass for c in q.results())
        self.assertListEqual(["infoflow", "infoflow3"], defaults)

    def test_030_default_range(self):
        """Default query: default_range setting."""
        q = DefaultQuery(self.p, default_range="high")

        defaults = sorted(c.tclass for c in q.results())
        self.assertListEqual(["infoflow7"], defaults)

    def test_900_invalid_ruletype(self):
        """Default query: invalid ruletype"""
        with self.assertRaises(InvalidDefaultType):
            q = DefaultQuery(self.p, ruletype=["INVALID"])

    def test_901_invalid_class(self):
        """Default query: invalid object class"""
        with self.assertRaises(InvalidClass):
            q = DefaultQuery(self.p, tclass=["INVALID"])

    def test_902_invalid_default_value(self):
        """Default query: invalid default value"""
        with self.assertRaises(InvalidDefaultValue):
            q = DefaultQuery(self.p, default="INVALID")

    def test_903_invalid_default_range(self):
        """Default query: invalid default range"""
        with self.assertRaises(InvalidDefaultRange):
            q = DefaultQuery(self.p, default_range="INVALID")
