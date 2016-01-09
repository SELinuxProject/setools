# Copyright 2016, Tresys Technology, LLC
#
# This file is part of SETools.
#
# SETools is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation, either version 2.1 of
# the License, or (at your option) any later version.
#
# SETools is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with SETools.  If not, see
# <http://www.gnu.org/licenses/>.
#
from collections import namedtuple

from .descriptors import DiffResultDescriptor
from .difference import Difference, SymbolWrapper, Wrapper

modified_cat_record = namedtuple("modified_category", ["added_aliases",
                                                       "removed_aliases",
                                                       "matched_aliases"])


class CategoriesDifference(Difference):

    """Determine the difference in categories between two policies."""

    added_categories = DiffResultDescriptor("diff_categories")
    removed_categories = DiffResultDescriptor("diff_categories")
    modified_categories = DiffResultDescriptor("diff_categories")

    def diff_categories(self):
        """Generate the difference in categories between the policies."""

        self.log.info(
            "Generating category differences from {0.left_policy} to {0.right_policy}".format(self))

        self.added_categories, self.removed_categories, matched_categories = self._set_diff(
            (SymbolWrapper(c) for c in self.left_policy.categories()),
            (SymbolWrapper(c) for c in self.right_policy.categories()))

        self.modified_categories = dict()

        for left_category, right_category in matched_categories:
            # Criteria for modified categories
            # 1. change to aliases
            added_aliases, removed_aliases, matched_aliases = self._set_diff(
                left_category.aliases(), right_category.aliases())

            if added_aliases or removed_aliases:
                self.modified_categories[left_category] = modified_cat_record(added_aliases,
                                                                              removed_aliases,
                                                                              matched_aliases)

    #
    # Internal functions
    #
    def _reset_diff(self):
        """Reset diff results on policy changes."""
        self.log.debug("Resetting category differences")
        self.added_categories = None
        self.removed_categories = None
        self.modified_categories = None


class LevelWrapper(Wrapper):

    """Wrap levels to allow comparisons."""

    def __init__(self, level):
        self.origin = level
        self.sensitivity = SymbolWrapper(level.sensitivity)
        self.categories = set(SymbolWrapper(c) for c in level.categories())

    def __eq__(self, other):
        try:
            return self.sensitivity == other.sensitivity and \
                   self.categories == other.categories
        except AttributeError:
            # comparing an MLS policy to non-MLS policy will result in
            # other being None
            return False


class RangeWrapper(Wrapper):

    """
    Wrap ranges to allow comparisons.

    This only compares the low and high levels of the range.
    It does not detect additions/removals/modifications
    to levels between the low and high levels of the range.
    """

    def __init__(self, range_):
        self.origin = range_
        self.low = LevelWrapper(range_.low)
        self.high = LevelWrapper(range_.high)

    def __eq__(self, other):
        try:
            return self.low == other.low and \
                   self.high == other.high
        except AttributeError:
            # comparing an MLS policy to non-MLS policy will result in
            # other being None
            return False
