# Copyright 2014, Tresys Technology, LLC
#
# SPDX-License-Identifier: GPL-2.0-only
#
import os
import unittest

from setools import PolCapQuery

from .policyrep.util import compile_policy


class PolCapQueryTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.p = compile_policy("tests/polcapquery.conf")

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.p.path)

    def test_000_unset(self):
        """Policy capability query with no criteria"""
        # query with no parameters gets all capabilities.
        allcaps = sorted(self.p.polcaps())

        q = PolCapQuery(self.p)
        qcaps = sorted(q.results())

        self.assertListEqual(allcaps, qcaps)

    def test_001_name_exact(self):
        """Policy capability query with exact match"""
        q = PolCapQuery(self.p, name="open_perms", name_regex=False)

        caps = sorted(str(c) for c in q.results())
        self.assertListEqual(["open_perms"], caps)

    def test_002_name_regex(self):
        """Policy capability query with regex match"""
        q = PolCapQuery(self.p, name="pe?er", name_regex=True)

        caps = sorted(str(c) for c in q.results())
        self.assertListEqual(["network_peer_controls", "open_perms"], caps)
