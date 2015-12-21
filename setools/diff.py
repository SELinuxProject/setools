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

from .policyrep.exception import NoCommon

__all__ = ['PolicyDifference']


modified_commons_record = namedtuple("modified_common", ["added_perms",
                                                         "removed_perms",
                                                         "matched_perms"])

modified_classes_record = namedtuple("modified_class", ["added_perms",
                                                        "removed_perms",
                                                        "matched_perms"])

modified_roles_record = namedtuple("modified_role", ["added_types",
                                                     "removed_types",
                                                     "matched_types"])

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
    # Common differences
    #
    added_commons = DiffResultDescriptor("diff_commons")
    removed_commons = DiffResultDescriptor("diff_commons")
    modified_commons = DiffResultDescriptor("diff_commons")

    def diff_commons(self):
        """Generate the difference in commons between the policies."""

        self.log.info(
            "Generating common differences from {0.left_policy} to {0.right_policy}".format(self))

        self.added_commons, self.removed_commons, matched_commons = self._set_diff(
            self.left_policy.commons(), self.right_policy.commons())

        self.modified_commons = dict()

        for name in matched_commons:
            # Criteria for modified commons
            # 1. change to permissions
            left_common = self.left_policy.lookup_common(name)
            right_common = self.right_policy.lookup_common(name)

            added_perms, removed_perms, matched_perms = self._set_diff(left_common.perms,
                                                                       right_common.perms)

            if added_perms or removed_perms:
                self.modified_commons[name] = modified_commons_record(added_perms,
                                                                      removed_perms,
                                                                      matched_perms)

    #
    # Object class differences
    #
    added_classes = DiffResultDescriptor("diff_classes")
    removed_classes = DiffResultDescriptor("diff_classes")
    modified_classes = DiffResultDescriptor("diff_classes")

    def diff_classes(self):
        """Generate the difference in object classes between the policies."""

        self.log.info(
            "Generating class differences from {0.left_policy} to {0.right_policy}".format(self))

        self.added_classes, self.removed_classes, matched_classes = self._set_diff(
            self.left_policy.classes(), self.right_policy.classes())

        self.modified_classes = dict()

        for name in matched_classes:
            # Criteria for modified classes
            # 1. change to permissions (inherited common is expanded)
            left_class = self.left_policy.lookup_class(name)
            right_class = self.right_policy.lookup_class(name)

            left_perms = left_class.perms
            try:
                left_perms |= left_class.common.perms
            except NoCommon:
                pass

            right_perms = right_class.perms
            try:
                right_perms |= right_class.common.perms
            except NoCommon:
                pass

            added_perms, removed_perms, matched_perms = self._set_diff(left_perms, right_perms)

            if added_perms or removed_perms:
                self.modified_classes[name] = modified_classes_record(added_perms,
                                                                      removed_perms,
                                                                      matched_perms)

    #
    # Role differences
    #
    added_roles = DiffResultDescriptor("diff_roles")
    removed_roles = DiffResultDescriptor("diff_roles")
    modified_roles = DiffResultDescriptor("diff_roles")

    def diff_roles(self):
        """Generate the difference in roles between the policies."""

        self.log.info(
            "Generating role differences from {0.left_policy} to {0.right_policy}".format(self))

        self.added_roles, self.removed_roles, matched_roles = self._set_diff(
            self.left_policy.roles(), self.right_policy.roles())

        self.modified_roles = dict()

        for name in matched_roles:
            # Criteria for modified roles
            # 1. change to type set, or
            # 2. change to attribute set (not implemented)
            left_role = self.left_policy.lookup_role(name)
            right_role = self.right_policy.lookup_role(name)

            added_types, removed_types, matched_types = self._set_diff(left_role.types(),
                                                                       right_role.types())

            if added_types or removed_types:
                self.modified_roles[name] = modified_roles_record(added_types,
                                                                  removed_types,
                                                                  matched_types)

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
        self.added_commons = None
        self.removed_commons = None
        self.modified_commons = None
        self.added_classes = None
        self.removed_classes = None
        self.modified_classes = None
        self.added_roles = None
        self.removed_roles = None
        self.modified_roles = None
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
