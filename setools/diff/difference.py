# Copyright 2015, Tresys Technology, LLC
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
import logging


class Difference(object):

    """Base class for all policy differences."""

    def __init__(self, left_policy, right_policy):
        self.log = logging.getLogger(self.__class__.__name__)
        self.left_policy = left_policy
        self.right_policy = right_policy

    #
    # Policies to compare
    #
    @property
    def left_policy(self):
        return self._left_policy

    @left_policy.setter
    def left_policy(self, policy):
        self.log.info("Policy diff left policy set to {0}".format(policy))
        self._left_policy = policy
        self._reset_diff()

    @property
    def right_policy(self):
        return self._right_policy

    @right_policy.setter
    def right_policy(self, policy):
        self.log.info("Policy diff right policy set to {0}".format(policy))
        self._right_policy = policy
        self._reset_diff()

    #
    # Internal functions
    #
    def _reset_diff(self):
        """Reset diff results on policy changes."""
        raise NotImplementedError

    @staticmethod
    def _set_diff(left, right):
        """
        Standard diff of two sets.

        Parameters:
        left        An iterable
        right       An iterable

        Return:
        tuple       (added, removed, matched)

        added       Set of items in right but not left
        removed     Set of items in left but not right
        matched     Set of items in both left and right
        """

        left_items = set(str(l) for l in left)
        right_items = set(str(r) for r in right)
        added_items = right_items - left_items
        removed_items = left_items - right_items
        matched_items = left_items & right_items

        return added_items, removed_items, matched_items
