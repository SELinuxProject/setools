# Copyright 2015, Tresys Technology, LLC
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

try:
    from unittest.mock import Mock
except ImportError:
    from mock import Mock

from setools import SELinuxPolicy
from setools.policyrep import qpol
from setools.policyrep.mls import sensitivity_factory, category_factory, level_factory, \
                                  range_factory, level_decl_factory, \
                                  MLSDisabled, InvalidLevel, InvalidRange


class SensitivityFactoryTest(unittest.TestCase):

    def setUp(self):
        self.p = SELinuxPolicy("tests/policyrep/mls.conf")

    def test_000_mls_disabled(self):
        """Sensitivity factory on MLS-disabled policy."""
        mock_p = Mock(qpol.qpol_policy_t)
        mock_p.capability.return_value = False
        self.assertRaises(MLSDisabled, sensitivity_factory, mock_p, None)


class CategoryFactoryTest(unittest.TestCase):

    def setUp(self):
        self.p = SELinuxPolicy("tests/policyrep/mls.conf")

    def test_000_mls_disabled(self):
        """Category factory on MLS-disabled policy."""
        mock_p = Mock(qpol.qpol_policy_t)
        mock_p.capability.return_value = False
        self.assertRaises(MLSDisabled, category_factory, mock_p, None)


class LevelDeclFactoryTest(unittest.TestCase):

    def setUp(self):
        self.p = SELinuxPolicy("tests/policyrep/mls.conf")

    def test_000_mls_disabled(self):
        """Level declaration factory on MLS-disabled policy."""
        mock_p = Mock(qpol.qpol_policy_t)
        mock_p.capability.return_value = False
        self.assertRaises(MLSDisabled, level_decl_factory, mock_p, None)


class LevelFactoryTest(unittest.TestCase):

    def setUp(self):
        self.p = SELinuxPolicy("tests/policyrep/mls.conf")

    def test_000_mls_disabled(self):
        """Level factory on MLS-disabled policy."""
        mock_p = Mock(qpol.qpol_policy_t)
        mock_p.capability.return_value = False
        self.assertRaises(MLSDisabled, level_factory, mock_p, None)

    def test_300_level_lookup_no_cats(self):
        """Level lookup with no categories."""
        levelobj = level_factory(self.p.policy, "s2")
        self.assertEqual(str(levelobj), "s2")

    def test_301_level_lookup_cat_range(self):
        """Level lookup with category range."""
        levelobj = level_factory(self.p.policy, "s1:c0.c13")
        self.assertEqual(str(levelobj), "s1:c0.c13")

    def test_302_level_lookup_complex_cats(self):
        """Level lookup with complex category set."""
        levelobj = level_factory(self.p.policy, "s2:c0.c5,c7,c9.c11,c13")
        self.assertEqual(str(levelobj), "s2:c0.c5,c7,c9.c11,c13")

    def test_303_level_lookup_bad1(self):
        """Level lookup with garbage."""
        self.assertRaises(InvalidLevel, level_factory, self.p.policy, "FAIL")

    def test_304_level_lookup_bad2(self):
        """Level lookup with : in garbage."""
        self.assertRaises(InvalidLevel, level_factory, self.p.policy, "FAIL:BAD")

    def test_305_level_lookup_bad_cat(self):
        """Level lookup with invalid category."""
        self.assertRaises(InvalidLevel, level_factory, self.p.policy, "s0:FAIL")

    def test_306_level_lookup_bad_cat_range(self):
        """Level lookup with backwards category range."""
        self.assertRaises(InvalidLevel, level_factory, self.p.policy, "s0:c4.c0")

    def test_306_level_lookup_cat_not_assoc(self):
        """Level lookup with category not associated with sensitivity."""
        # c4 is not associated with s0.
        self.assertRaises(InvalidLevel, level_factory, self.p.policy, "s0:c0,c4")


class RangeFactoryTest(unittest.TestCase):

    def setUp(self):
        self.p = SELinuxPolicy("tests/policyrep/mls.conf")

    def test_000_mls_disabled(self):
        """Range factory on MLS-disabled policy."""
        mock_p = Mock(qpol.qpol_policy_t)
        mock_p.capability.return_value = False
        self.assertRaises(MLSDisabled, range_factory, mock_p, None)

    def test_400_range_lookup_single_level(self):
        """Range lookup with single-level range."""
        rangeobj = range_factory(self.p.policy, "s0")
        self.assertEqual(str(rangeobj), "s0")

    def test_401_range_lookup_single_level_redundant(self):
        """Range lookup with single-level range (same range listed twice)."""
        rangeobj = range_factory(self.p.policy, "s1-s1")
        self.assertEqual(str(rangeobj), "s1")

    def test_402_range_lookup_simple(self):
        """Range lookup with simple range."""
        rangeobj = range_factory(self.p.policy, "s0-s1:c0.c10")
        self.assertEqual(str(rangeobj), "s0 - s1:c0.c10")

    def test_403_range_lookup_no_cats(self):
        """Range lookup with no categories."""
        rangeobj = range_factory(self.p.policy, "s0-s1")
        self.assertEqual(str(rangeobj), "s0 - s1")

    def test_404_range_lookup_complex(self):
        """Range lookup with complex category set."""
        rangeobj = range_factory(self.p.policy, "s0:c0.c2-s2:c0.c5,c7,c9.c11,c13")
        self.assertEqual(str(rangeobj), "s0:c0.c2 - s2:c0.c5,c7,c9.c11,c13")

    def test_405_range_lookup_non_dom(self):
        """Range lookup with non-dominating high level."""
        self.assertRaises(InvalidRange, range_factory, self.p.policy, "s1-s0")

    def test_406_range_lookup_invalid_range(self):
        """Range lookup with an invalid range (low)."""
        # c13 is not associated with s0.
        self.assertRaises(InvalidRange, range_factory, self.p.policy, "s0:c13-s2:c13")
