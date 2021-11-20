# Copyright 2014-2015, Tresys Technology, LLC
# Copyright 2019, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: GPL-2.0-only
#
import os
import unittest

from setools import TypeQuery

from .policyrep.util import compile_policy


class TypeQueryTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.p = compile_policy("tests/typequery.conf")

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.p.path)

    def test_000_unset(self):
        """Type query with no criteria."""
        # query with no parameters gets all types.
        alltypes = sorted(self.p.types())

        q = TypeQuery(self.p)
        qtypes = sorted(q.results())

        self.assertListEqual(alltypes, qtypes)

    def test_001_name_exact(self):
        """Type query with exact name match."""
        q = TypeQuery(self.p, name="test1")

        types = sorted(str(t) for t in q.results())
        self.assertListEqual(["test1"], types)

    def test_002_name_regex(self):
        """Type query with regex name match."""
        q = TypeQuery(self.p, name="test2(a|b)", name_regex=True)

        types = sorted(str(t) for t in q.results())
        self.assertListEqual(["test2a", "test2b"], types)

    def test_010_attr_intersect(self):
        """Type query with attribute set intersection."""
        q = TypeQuery(self.p, attrs=["test10a", "test10b"])

        types = sorted(str(t) for t in q.results())
        self.assertListEqual(["test10t1", "test10t2", "test10t3",
                              "test10t4", "test10t5", "test10t6"], types)

    def test_011_attr_equality(self):
        """Type query with attribute set equality."""
        q = TypeQuery(self.p, attrs=["test11a", "test11b"], attrs_equal=True)

        types = sorted(str(t) for t in q.results())
        self.assertListEqual(["test11t2"], types)

    def test_012_attr_regex(self):
        """Type query with attribute regex match."""
        q = TypeQuery(self.p, attrs="test12(a|b)", attrs_regex=True)

        types = sorted(str(t) for t in q.results())
        self.assertListEqual(["test12t1", "test12t2", "test12t3",
                              "test12t4", "test12t5", "test12t6"], types)

    def test_020_alias_exact(self):
        """Type query with exact alias match."""
        q = TypeQuery(self.p, alias="test20a")

        types = sorted(str(t) for t in q.results())
        self.assertListEqual(["test20t1"], types)

    def test_021_alias_regex(self):
        """Type query with regex alias match."""
        q = TypeQuery(self.p, alias="test21(a|b)", alias_regex=True)

        types = sorted(str(t) for t in q.results())
        self.assertListEqual(["test21t1", "test21t2"], types)

    def test_022_alias_dereference(self):
        """Type query with alias dereference."""
        q = TypeQuery(self.p, name="test22alias", alias_deref=True)

        types = sorted(str(t) for t in q.results())
        self.assertListEqual(["test22"], types)

    def test_030_permissive(self):
        """Type query with permissive match"""
        q = TypeQuery(self.p, permissive=True)

        types = sorted(str(t) for t in q.results())
        self.assertListEqual(["test30"], types)
