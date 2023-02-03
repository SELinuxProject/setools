# Copyright 2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: GPL-2.0-only
#
import os
import unittest

from setools import CategoryQuery

from .policyrep.util import compile_policy


class CategoryQueryTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.p = compile_policy("tests/categoryquery.conf")

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.p.path)

    def test_000_unset(self):
        """MLS category query with no criteria."""
        # query with no parameters gets all categories.
        allcats = sorted(str(c) for c in self.p.categories())

        q = CategoryQuery(self.p)
        qcats = sorted(str(c) for c in q.results())

        self.assertListEqual(allcats, qcats)

    def test_001_name_exact(self):
        """MLS category query with exact name match."""
        q = CategoryQuery(self.p, name="test1")

        cats = sorted(str(c) for c in q.results())
        self.assertListEqual(["test1"], cats)

    def test_002_name_regex(self):
        """MLS category query with regex name match."""
        q = CategoryQuery(self.p, name="test2(a|b)", name_regex=True)

        cats = sorted(str(c) for c in q.results())
        self.assertListEqual(["test2a", "test2b"], cats)

    def test_010_alias_exact(self):
        """MLS category query with exact alias match."""
        q = CategoryQuery(self.p, alias="test10a")

        cats = sorted(str(t) for t in q.results())
        self.assertListEqual(["test10c1"], cats)

    def test_011_alias_regex(self):
        """MLS category query with regex alias match."""
        q = CategoryQuery(self.p, alias="test11(a|b)", alias_regex=True)

        cats = sorted(str(t) for t in q.results())
        self.assertListEqual(["test11c1", "test11c2"], cats)
