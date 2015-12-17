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
from collections import namedtuple
from weakref import WeakKeyDictionary

__all__ = ['PolicyDifference']


modified_types_record = namedtuple("modified_type", ["added_attributes",
                                                     "removed_attributes",
                                                     "matched_attributes",
                                                     "modified_permissive",
                                                     "permissive",
                                                     "added_aliases",
                                                     "removed_aliases",
                                                     "matched_aliases"])


class DiffResultDescriptor(object):

    """Descriptor for managing diff results."""

    # @properties could be used instead, but there are so
    # many result attributes, this will keep the code more compact.

    def __init__(self, diff_function):
        self.diff_function = diff_function

        # use weak references so instances can be
        # garbage collected, rather than unnecessarily
        # kept around due to this descriptor.
        self.instances = WeakKeyDictionary()

    def __get__(self, obj, objtype=None):
        if obj is None:
            return self

        if self.instances.setdefault(obj, None) is None:
            diff = getattr(obj, self.diff_function)
            diff()

        return self.instances[obj]

    def __set__(self, obj, value):
        self.instances[obj] = value


class PolicyDifference(object):

    """
    Determine the differences between two policies.

    All results are represented as str rather than the
    original Python objects.  This was done because the
    source of the object becomes less clear (Python
    set logic doesn't have any guarantees for set
    intersection). Using str will prevent problems
    if you expect to be using a symbol but it is
    coming from the wrong policy.
    """

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
        self._left_policy = policy
        self._reset_diff()

    @property
    def right_policy(self):
        return self._right_policy

    @right_policy.setter
    def right_policy(self, policy):
        self._right_policy = policy
        self._reset_diff()

    #
    # Type differences
    #
    added_types = DiffResultDescriptor("diff_types")
    removed_types = DiffResultDescriptor("diff_types")
    modified_types = DiffResultDescriptor("diff_types")

    def diff_types(self):
        """Generate the difference in types between the policies."""

        self.log.info(
            "Generating type differences from {0.left_policy} to {0.right_policy}".format(self))

        self.added_types, self.removed_types, matched_types = self._set_diff(
            self.left_policy.types(), self.right_policy.types())

        self.modified_types = dict()

        for name in matched_types:
            # Criteria for modified types
            # 1. change to attribute set, or
            # 2. change to alias set, or
            # 3. different permissive setting
            left_type = self.left_policy.lookup_type(name)
            right_type = self.right_policy.lookup_type(name)

            added_attr, removed_attr, matched_attr = self._set_diff(left_type.attributes(),
                                                                    right_type.attributes())

            added_aliases, removed_aliases, matched_aliases = self._set_diff(left_type.aliases(),
                                                                             right_type.aliases())

            left_permissive = left_type.ispermissive
            right_permissive = right_type.ispermissive
            mod_permissive = left_permissive != right_permissive

            if added_attr or removed_attr or added_aliases or removed_aliases or mod_permissive:
                self.modified_types[name] = modified_types_record(added_attr,
                                                                  removed_attr,
                                                                  matched_attr,
                                                                  mod_permissive,
                                                                  left_permissive,
                                                                  added_aliases,
                                                                  removed_aliases,
                                                                  matched_aliases)

    #
    # Internal functions
    #
    def _reset_diff(self):
        """Reset diff results on policy changes."""
        self.added_types = None
        self.removed_types = None
        self.modified_types = None

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
