# Derived from tests/portconquery.py
#
# SPDX-License-Identifier: GPL-2.0-only
#
import os
import unittest

from setools import PcideviceconQuery

from .policyrep.util import compile_policy


class PcideviceconQueryTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.p = compile_policy("tests/pcideviceconquery.conf", xen=True)

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.p.path)

    def test_000_unset(self):
        """Pcidevicecon query with no criteria"""
        # query with no parameters gets all PCI devices.
        rules = sorted(self.p.pcidevicecons())

        q = PcideviceconQuery(self.p)
        q_rules = sorted(q.results())

        self.assertListEqual(rules, q_rules)

    def test_010_user_exact(self):
        """Pcidevicecon query with context user exact match"""
        q = PcideviceconQuery(self.p, user="user10", user_regex=False)

        device = sorted(p.device for p in q.results())
        self.assertListEqual([(10)], device)

    def test_011_user_regex(self):
        """Pcidevicecon query with context user regex match"""
        q = PcideviceconQuery(self.p, user="user11(a|b)", user_regex=True)

        device = sorted(p.device for p in q.results())
        self.assertListEqual([(11), (11000)], device)

    def test_020_role_exact(self):
        """Pcidevicecon query with context role exact match"""
        q = PcideviceconQuery(self.p, role="role20_r", role_regex=False)

        device = sorted(p.device for p in q.results())
        self.assertListEqual([(20)], device)

    def test_021_role_regex(self):
        """Pcidevicecon query with context role regex match"""
        q = PcideviceconQuery(self.p, role="role21(a|c)_r", role_regex=True)

        device = sorted(p.device for p in q.results())
        self.assertListEqual([(21), (21001)], device)

    def test_030_type_exact(self):
        """Pcidevicecon query with context type exact match"""
        q = PcideviceconQuery(self.p, type_="type30", type_regex=False)

        device = sorted(p.device for p in q.results())
        self.assertListEqual([(30)], device)

    def test_031_type_regex(self):
        """Pcidevicecon query with context type regex match"""
        q = PcideviceconQuery(self.p, type_="type31(b|c)", type_regex=True)

        device = sorted(p.device for p in q.results())
        self.assertListEqual([(31000), (31001)], device)

    def test_040_range_exact(self):
        """Pcidevicecon query with context range exact match"""
        q = PcideviceconQuery(self.p, range_="s0:c1 - s0:c0.c4")

        device = sorted(p.device for p in q.results())
        self.assertListEqual([(40)], device)

    def test_041_range_overlap1(self):
        """Pcidevicecon query with context range overlap match (equal)"""
        q = PcideviceconQuery(self.p, range_="s1:c1 - s1:c0.c4", range_overlap=True)

        device = sorted(p.device for p in q.results())
        self.assertListEqual([(41)], device)

    def test_041_range_overlap2(self):
        """Pcidevicecon query with context range overlap match (subset)"""
        q = PcideviceconQuery(self.p, range_="s1:c1,c2 - s1:c0.c3", range_overlap=True)

        device = sorted(p.device for p in q.results())
        self.assertListEqual([(41)], device)

    def test_041_range_overlap3(self):
        """Pcidevicecon query with context range overlap match (superset)"""
        q = PcideviceconQuery(self.p, range_="s1 - s1:c0.c4", range_overlap=True)

        device = sorted(p.device for p in q.results())
        self.assertListEqual([(41)], device)

    def test_041_range_overlap4(self):
        """Pcidevicecon query with context range overlap match (overlap low level)"""
        q = PcideviceconQuery(self.p, range_="s1 - s1:c1,c2", range_overlap=True)

        device = sorted(p.device for p in q.results())
        self.assertListEqual([(41)], device)

    def test_041_range_overlap5(self):
        """Pcidevicecon query with context range overlap match (overlap high level)"""
        q = PcideviceconQuery(self.p, range_="s1:c1,c2 - s1:c0.c4", range_overlap=True)

        device = sorted(p.device for p in q.results())
        self.assertListEqual([(41)], device)

    def test_042_range_subset1(self):
        """Pcidevicecon query with context range subset match"""
        q = PcideviceconQuery(self.p, range_="s2:c1,c2 - s2:c0.c3", range_overlap=True)

        device = sorted(p.device for p in q.results())
        self.assertListEqual([(42)], device)

    def test_042_range_subset2(self):
        """Pcidevicecon query with context range subset match (equal)"""
        q = PcideviceconQuery(self.p, range_="s2:c1 - s2:c1.c3", range_overlap=True)

        device = sorted(p.device for p in q.results())
        self.assertListEqual([(42)], device)

    def test_043_range_superset1(self):
        """Pcidevicecon query with context range superset match"""
        q = PcideviceconQuery(self.p, range_="s3 - s3:c0.c4", range_superset=True)

        device = sorted(p.device for p in q.results())
        self.assertListEqual([(43)], device)

    def test_043_range_superset2(self):
        """Pcidevicecon query with context range superset match (equal)"""
        q = PcideviceconQuery(self.p, range_="s3:c1 - s3:c1.c3", range_superset=True)

        device = sorted(p.device for p in q.results())
        self.assertListEqual([(43)], device)

    def test_044_range_proper_subset1(self):
        """Pcidevicecon query with context range proper subset match"""
        q = PcideviceconQuery(self.p, range_="s4:c1,c2", range_subset=True, range_proper=True)

        device = sorted(p.device for p in q.results())
        self.assertListEqual([(44)], device)

    def test_044_range_proper_subset2(self):
        """Pcidevicecon query with context range proper subset match (equal)"""
        q = PcideviceconQuery(self.p,
                              range_="s4:c1 - s4:c1.c3", range_subset=True, range_proper=True)

        device = sorted(p.device for p in q.results())
        self.assertListEqual([], device)

    def test_044_range_proper_subset3(self):
        """Pcidevicecon query with context range proper subset match (equal low only)"""
        q = PcideviceconQuery(self.p,
                              range_="s4:c1 - s4:c1.c2", range_subset=True, range_proper=True)

        device = sorted(p.device for p in q.results())
        self.assertListEqual([(44)], device)

    def test_044_range_proper_subset4(self):
        """Pcidevicecon query with context range proper subset match (equal high only)"""
        q = PcideviceconQuery(self.p,
                              range_="s4:c1,c2 - s4:c1.c3", range_subset=True, range_proper=True)

        device = sorted(p.device for p in q.results())
        self.assertListEqual([(44)], device)

    def test_045_range_proper_superset1(self):
        """Pcidevicecon query with context range proper superset match"""
        q = PcideviceconQuery(self.p,
                              range_="s5 - s5:c0.c4", range_superset=True, range_proper=True)

        device = sorted(p.device for p in q.results())
        self.assertListEqual([(45)], device)

    def test_045_range_proper_superset2(self):
        """Pcidevicecon query with context range proper superset match (equal)"""
        q = PcideviceconQuery(self.p,
                              range_="s5:c1 - s5:c1.c3", range_superset=True, range_proper=True)

        device = sorted(p.device for p in q.results())
        self.assertListEqual([], device)

    def test_045_range_proper_superset3(self):
        """Pcidevicecon query with context range proper superset match (equal low)"""
        q = PcideviceconQuery(self.p,
                              range_="s5:c1 - s5:c1.c4", range_superset=True, range_proper=True)

        device = sorted(p.device for p in q.results())
        self.assertListEqual([(45)], device)

    def test_045_range_proper_superset4(self):
        """Pcidevicecon query with context range proper superset match (equal high)"""
        q = PcideviceconQuery(self.p,
                              range_="s5 - s5:c1.c3", range_superset=True, range_proper=True)

        device = sorted(p.device for p in q.results())
        self.assertListEqual([(45)], device)
