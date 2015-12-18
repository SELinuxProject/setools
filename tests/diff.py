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

from setools import SELinuxPolicy, PolicyDifference


class PolicyDifferenceTest(unittest.TestCase):

    """Policy difference tests."""

    def setUp(self):
        self.diff = PolicyDifference(SELinuxPolicy("tests/diff_left.conf"),
                                     SELinuxPolicy("tests/diff_right.conf"))

    def test_added_types(self):
        """Diff: added type"""
        self.assertSetEqual(set(["added_type"]), self.diff.added_types)

    def test_removed_types(self):
        """Diff: modified type"""
        self.assertSetEqual(set(["removed_type"]), self.diff.removed_types)

    def test_modified_types_count(self):
        """Diff: total modified types"""
        self.assertEqual(6, len(self.diff.modified_types))

    def test_modified_types_remove_attr(self):
        """Diff: modified type with removed attribute."""
        self.assertIn("modified_remove_attr", self.diff.modified_types)
        removed_attrs = self.diff.modified_types["modified_remove_attr"].removed_attributes
        self.assertSetEqual(set(["an_attr"]), removed_attrs)
        self.assertFalse(self.diff.modified_types["modified_remove_attr"].added_attributes)
        self.assertFalse(self.diff.modified_types["modified_remove_attr"].matched_attributes)
        self.assertFalse(self.diff.modified_types["modified_remove_attr"].modified_permissive)
        self.assertFalse(self.diff.modified_types["modified_remove_attr"].permissive)
        self.assertFalse(self.diff.modified_types["modified_remove_attr"].added_aliases)
        self.assertFalse(self.diff.modified_types["modified_remove_attr"].removed_aliases)
        self.assertFalse(self.diff.modified_types["modified_remove_attr"].matched_aliases)

    def test_modified_types_remove_alias(self):
        """Diff: modified type with removed alias."""
        self.assertIn("modified_remove_alias", self.diff.modified_types)
        removed_alias = self.diff.modified_types["modified_remove_alias"].removed_aliases
        self.assertSetEqual(set(["an_alias"]), removed_alias)
        self.assertFalse(self.diff.modified_types["modified_remove_alias"].added_attributes)
        self.assertFalse(self.diff.modified_types["modified_remove_alias"].removed_attributes)
        self.assertFalse(self.diff.modified_types["modified_remove_alias"].matched_attributes)
        self.assertFalse(self.diff.modified_types["modified_remove_alias"].modified_permissive)
        self.assertFalse(self.diff.modified_types["modified_remove_alias"].permissive)
        self.assertFalse(self.diff.modified_types["modified_remove_alias"].added_aliases)
        self.assertFalse(self.diff.modified_types["modified_remove_alias"].matched_aliases)

    def test_modified_types_remove_permissive(self):
        """Diff: modified type with removed permissve."""
        self.assertIn("modified_remove_permissive", self.diff.modified_types)
        self.assertFalse(self.diff.modified_types["modified_remove_permissive"].added_attributes)
        self.assertFalse(self.diff.modified_types["modified_remove_permissive"].removed_attributes)
        self.assertFalse(self.diff.modified_types["modified_remove_permissive"].matched_attributes)
        self.assertTrue(self.diff.modified_types["modified_remove_permissive"].modified_permissive)
        self.assertTrue(self.diff.modified_types["modified_remove_permissive"].permissive)
        self.assertFalse(self.diff.modified_types["modified_remove_permissive"].added_aliases)
        self.assertFalse(self.diff.modified_types["modified_remove_permissive"].removed_aliases)
        self.assertFalse(self.diff.modified_types["modified_remove_permissive"].matched_aliases)

    def test_modified_types_add_attr(self):
        """Diff: modified type with added attribute."""
        self.assertIn("modified_add_attr", self.diff.modified_types)
        added_attrs = self.diff.modified_types["modified_add_attr"].added_attributes
        self.assertSetEqual(set(["an_attr"]), added_attrs)
        self.assertFalse(self.diff.modified_types["modified_add_attr"].removed_attributes)
        self.assertFalse(self.diff.modified_types["modified_add_attr"].matched_attributes)
        self.assertFalse(self.diff.modified_types["modified_add_attr"].modified_permissive)
        self.assertFalse(self.diff.modified_types["modified_add_attr"].permissive)
        self.assertFalse(self.diff.modified_types["modified_add_attr"].added_aliases)
        self.assertFalse(self.diff.modified_types["modified_add_attr"].removed_aliases)
        self.assertFalse(self.diff.modified_types["modified_add_attr"].matched_aliases)

    def test_modified_types_add_alias(self):
        """Diff: modified type with added alias."""
        self.assertIn("modified_add_alias", self.diff.modified_types)
        added_alias = self.diff.modified_types["modified_add_alias"].added_aliases
        self.assertSetEqual(set(["an_alias"]), added_alias)
        self.assertFalse(self.diff.modified_types["modified_add_alias"].added_attributes)
        self.assertFalse(self.diff.modified_types["modified_add_alias"].removed_attributes)
        self.assertFalse(self.diff.modified_types["modified_add_alias"].matched_attributes)
        self.assertFalse(self.diff.modified_types["modified_add_alias"].modified_permissive)
        self.assertFalse(self.diff.modified_types["modified_add_alias"].permissive)
        self.assertFalse(self.diff.modified_types["modified_add_alias"].removed_aliases)
        self.assertFalse(self.diff.modified_types["modified_add_alias"].matched_aliases)

    def test_modified_types_add_permissive(self):
        """Diff: modified type with added permissive."""
        self.assertIn("modified_add_permissive", self.diff.modified_types)
        self.assertFalse(self.diff.modified_types["modified_add_permissive"].added_attributes)
        self.assertFalse(self.diff.modified_types["modified_add_permissive"].removed_attributes)
        self.assertFalse(self.diff.modified_types["modified_add_permissive"].matched_attributes)
        self.assertTrue(self.diff.modified_types["modified_add_permissive"].modified_permissive)
        self.assertFalse(self.diff.modified_types["modified_add_permissive"].permissive)
        self.assertFalse(self.diff.modified_types["modified_add_permissive"].added_aliases)
        self.assertFalse(self.diff.modified_types["modified_add_permissive"].removed_aliases)
        self.assertFalse(self.diff.modified_types["modified_add_permissive"].matched_aliases)


class PolicyDifferenceTestNoDiff(unittest.TestCase):

    """Policy difference test with no policy differences."""

    def setUp(self):
        self.diff = PolicyDifference(SELinuxPolicy("tests/diff_left.conf"),
                                     SELinuxPolicy("tests/diff_left.conf"))

    def test_added_types(self):
        """NoDiff: no added types"""
        self.assertFalse(self.diff.added_types)

    def test_removed_types(self):
        """NoDiff: no removed types"""
        self.assertFalse(self.diff.removed_types)

    def test_modified_types(self):
        """NoDiff: no modified types"""
        self.assertFalse(self.diff.modified_types)
