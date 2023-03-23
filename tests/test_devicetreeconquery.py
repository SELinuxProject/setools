# Derived from tests/portconquery.py
#
# SPDX-License-Identifier: GPL-2.0-only
#
import os
import unittest

from setools import DevicetreeconQuery

from .policyrep.util import compile_policy


class DevicetreeconQueryTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.p = compile_policy("tests/devicetreeconquery.conf", xen=True)

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.p.path)

    def test_000_unset(self):
        """Devicetreecon query with no criteria"""
        # query with no parameters gets all PCI paths.
        rules = sorted(self.p.devicetreecons())

        q = DevicetreeconQuery(self.p)
        q_rules = sorted(q.results())

        self.assertListEqual(rules, q_rules)

    def test_010_user_exact(self):
        """Devicetreecon query with context user exact match"""
        q = DevicetreeconQuery(self.p, user="user10", user_regex=False)

        path = sorted(p.path for p in q.results())
        self.assertListEqual([("/dev/tree10")], path)

    def test_011_user_regex(self):
        """Devicetreecon query with context user regex match"""
        q = DevicetreeconQuery(self.p, user="user11(a|b)", user_regex=True)

        path = sorted(p.path for p in q.results())
        self.assertListEqual([("/dev/tree11"), ("/dev/tree11000")], path)

    def test_020_role_exact(self):
        """Devicetreecon query with context role exact match"""
        q = DevicetreeconQuery(self.p, role="role20_r", role_regex=False)

        path = sorted(p.path for p in q.results())
        self.assertListEqual([("/dev/tree20")], path)

    def test_021_role_regex(self):
        """Devicetreecon query with context role regex match"""
        q = DevicetreeconQuery(self.p, role="role21(a|c)_r", role_regex=True)

        path = sorted(p.path for p in q.results())
        self.assertListEqual([("/dev/tree21"), ("/dev/tree21001")], path)

    def test_030_type_exact(self):
        """Devicetreecon query with context type exact match"""
        q = DevicetreeconQuery(self.p, type_="type30", type_regex=False)

        path = sorted(p.path for p in q.results())
        self.assertListEqual([("/dev/tree30")], path)

    def test_031_type_regex(self):
        """Devicetreecon query with context type regex match"""
        q = DevicetreeconQuery(self.p, type_="type31(b|c)", type_regex=True)

        path = sorted(p.path for p in q.results())
        self.assertListEqual([("/dev/tree31000"), ("/dev/tree31001")], path)

    def test_040_range_exact(self):
        """Devicetreecon query with context range exact match"""
        q = DevicetreeconQuery(self.p, range_="s0:c1 - s0:c0.c4")

        path = sorted(p.path for p in q.results())
        self.assertListEqual([("/dev/tree40")], path)

    def test_041_range_overlap1(self):
        """Devicetreecon query with context range overlap match (equal)"""
        q = DevicetreeconQuery(self.p, range_="s1:c1 - s1:c0.c4", range_overlap=True)

        path = sorted(p.path for p in q.results())
        self.assertListEqual([("/dev/tree41")], path)

    def test_041_range_overlap2(self):
        """Devicetreecon query with context range overlap match (subset)"""
        q = DevicetreeconQuery(self.p, range_="s1:c1,c2 - s1:c0.c3", range_overlap=True)

        path = sorted(p.path for p in q.results())
        self.assertListEqual([("/dev/tree41")], path)

    def test_041_range_overlap3(self):
        """Devicetreecon query with context range overlap match (superset)"""
        q = DevicetreeconQuery(self.p, range_="s1 - s1:c0.c4", range_overlap=True)

        path = sorted(p.path for p in q.results())
        self.assertListEqual([("/dev/tree41")], path)

    def test_041_range_overlap4(self):
        """Devicetreecon query with context range overlap match (overlap low level)"""
        q = DevicetreeconQuery(self.p, range_="s1 - s1:c1,c2", range_overlap=True)

        path = sorted(p.path for p in q.results())
        self.assertListEqual([("/dev/tree41")], path)

    def test_041_range_overlap5(self):
        """Devicetreecon query with context range overlap match (overlap high level)"""
        q = DevicetreeconQuery(self.p, range_="s1:c1,c2 - s1:c0.c4", range_overlap=True)

        path = sorted(p.path for p in q.results())
        self.assertListEqual([("/dev/tree41")], path)

    def test_042_range_subset1(self):
        """Devicetreecon query with context range subset match"""
        q = DevicetreeconQuery(self.p, range_="s2:c1,c2 - s2:c0.c3", range_overlap=True)

        path = sorted(p.path for p in q.results())
        self.assertListEqual([("/dev/tree42")], path)

    def test_042_range_subset2(self):
        """Devicetreecon query with context range subset match (equal)"""
        q = DevicetreeconQuery(self.p, range_="s2:c1 - s2:c1.c3", range_overlap=True)

        path = sorted(p.path for p in q.results())
        self.assertListEqual([("/dev/tree42")], path)

    def test_043_range_superset1(self):
        """Devicetreecon query with context range superset match"""
        q = DevicetreeconQuery(self.p, range_="s3 - s3:c0.c4", range_superset=True)

        path = sorted(p.path for p in q.results())
        self.assertListEqual([("/dev/tree43")], path)

    def test_043_range_superset2(self):
        """Devicetreecon query with context range superset match (equal)"""
        q = DevicetreeconQuery(self.p, range_="s3:c1 - s3:c1.c3", range_superset=True)

        path = sorted(p.path for p in q.results())
        self.assertListEqual([("/dev/tree43")], path)

    def test_044_range_proper_subset1(self):
        """Devicetreecon query with context range proper subset match"""
        q = DevicetreeconQuery(self.p, range_="s4:c1,c2", range_subset=True, range_proper=True)

        path = sorted(p.path for p in q.results())
        self.assertListEqual([("/dev/tree44")], path)

    def test_044_range_proper_subset2(self):
        """Devicetreecon query with context range proper subset match (equal)"""
        q = DevicetreeconQuery(self.p,
                               range_="s4:c1 - s4:c1.c3", range_subset=True, range_proper=True)

        path = sorted(p.path for p in q.results())
        self.assertListEqual([], path)

    def test_044_range_proper_subset3(self):
        """Devicetreecon query with context range proper subset match (equal low only)"""
        q = DevicetreeconQuery(self.p,
                               range_="s4:c1 - s4:c1.c2", range_subset=True, range_proper=True)

        path = sorted(p.path for p in q.results())
        self.assertListEqual([("/dev/tree44")], path)

    def test_044_range_proper_subset4(self):
        """Devicetreecon query with context range proper subset match (equal high only)"""
        q = DevicetreeconQuery(self.p,
                               range_="s4:c1,c2 - s4:c1.c3", range_subset=True, range_proper=True)

        path = sorted(p.path for p in q.results())
        self.assertListEqual([("/dev/tree44")], path)

    def test_045_range_proper_superset1(self):
        """Devicetreecon query with context range proper superset match"""
        q = DevicetreeconQuery(self.p,
                               range_="s5 - s5:c0.c4", range_superset=True, range_proper=True)

        path = sorted(p.path for p in q.results())
        self.assertListEqual([("/dev/tree45")], path)

    def test_045_range_proper_superset2(self):
        """Devicetreecon query with context range proper superset match (equal)"""
        q = DevicetreeconQuery(self.p,
                               range_="s5:c1 - s5:c1.c3", range_superset=True, range_proper=True)

        path = sorted(p.path for p in q.results())
        self.assertListEqual([], path)

    def test_045_range_proper_superset3(self):
        """Devicetreecon query with context range proper superset match (equal low)"""
        q = DevicetreeconQuery(self.p,
                               range_="s5:c1 - s5:c1.c4", range_superset=True, range_proper=True)

        path = sorted(p.path for p in q.results())
        self.assertListEqual([("/dev/tree45")], path)

    def test_045_range_proper_superset4(self):
        """Devicetreecon query with context range proper superset match (equal high)"""
        q = DevicetreeconQuery(self.p,
                               range_="s5 - s5:c1.c3", range_superset=True, range_proper=True)

        path = sorted(p.path for p in q.results())
        self.assertListEqual([("/dev/tree45")], path)
