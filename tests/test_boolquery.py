# Copyright 2014, Tresys Technology, LLC
#
# SPDX-License-Identifier: GPL-2.0-only
#
import os
import unittest

from setools import BoolQuery

from .policyrep.util import compile_policy


class BoolQueryTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.p = compile_policy("tests/boolquery.conf")

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.p.path)

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
