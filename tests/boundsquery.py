# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: GPL-2.0-only
#
import os
import unittest

from setools import BoundsQuery, BoundsRuletype

from .policyrep.util import compile_policy


class BoundsQueryTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.p = compile_policy("tests/boundsquery.conf")

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.p.path)

    def test_000_unset(self):
        """Bounds query with no criteria."""
        # query with no parameters gets all bounds.
        allbounds = sorted(self.p.bounds())

        q = BoundsQuery(self.p)
        qbounds = sorted(q.results())

        self.assertListEqual(allbounds, qbounds)

    def test_001_parent_exact(self):
        """Bounds query with exact parent match."""
        q = BoundsQuery(self.p, parent="test1_parent", parent_regex=False)
        qbounds = sorted(q.results())
        self.assertEqual(1, len(qbounds))

        b = qbounds[0]
        self.assertEqual(BoundsRuletype.typebounds, b.ruletype)
        self.assertEqual("test1_parent", b.parent)
        self.assertEqual("test1_child", b.child)

    def test_002_parent_regex(self):
        """Bounds query with regex parent match."""
        q = BoundsQuery(self.p, parent="test2_parent?", parent_regex=True)
        qbounds = sorted(q.results())
        self.assertEqual(2, len(qbounds))

        b = qbounds[0]
        self.assertEqual(BoundsRuletype.typebounds, b.ruletype)
        self.assertEqual("test2_parent1", b.parent)
        self.assertEqual("test2_child2", b.child)

        b = qbounds[1]
        self.assertEqual(BoundsRuletype.typebounds, b.ruletype)
        self.assertEqual("test2_parent2", b.parent)
        self.assertEqual("test2_child1", b.child)

    def test_010_child_exact(self):
        """Bounds query with exact child match."""
        q = BoundsQuery(self.p, child="test10_child", child_regex=False)
        qbounds = sorted(q.results())
        self.assertEqual(1, len(qbounds))

        b = qbounds[0]
        self.assertEqual(BoundsRuletype.typebounds, b.ruletype)
        self.assertEqual("test10_parent", b.parent)
        self.assertEqual("test10_child", b.child)

    def test_011_child_regex(self):
        """Bounds query with regex child match."""
        q = BoundsQuery(self.p, child="test11_child?", child_regex=True)
        qbounds = sorted(q.results())
        self.assertEqual(2, len(qbounds))

        b = qbounds[0]
        self.assertEqual(BoundsRuletype.typebounds, b.ruletype)
        self.assertEqual("test11_parent1", b.parent)
        self.assertEqual("test11_child2", b.child)

        b = qbounds[1]
        self.assertEqual(BoundsRuletype.typebounds, b.ruletype)
        self.assertEqual("test11_parent2", b.parent)
        self.assertEqual("test11_child1", b.child)
