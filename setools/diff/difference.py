# Copyright 2015-2016, Tresys Technology, LLC
# Copyright 2018, Chris PeBenito <pebenito@ieee.org>
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
from abc import ABC, abstractmethod
from typing import Generic, Iterable, TypeVar

from ..policyrep import PolicyObject, PolicySymbol, SELinuxPolicy


class Difference:

    """Base class for all policy differences."""

    def __init__(self, left_policy: SELinuxPolicy, right_policy: SELinuxPolicy) -> None:
        self.log = logging.getLogger(__name__)
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
    def _reset_diff(self) -> None:
        """Reset diff results on policy changes."""
        raise NotImplementedError

    @staticmethod
    def _expand_generator(rule_list: Iterable, wrapper_class) -> Iterable:
        """Generator that yields a wrapped, expanded rule list."""
        # this is to delay creating any containers
        # as long as possible, since rule lists
        # are typically massive.
        for unexpanded_rule in rule_list:
            for expanded_rule in unexpanded_rule.expand():
                yield wrapper_class(expanded_rule)

    @staticmethod
    def _set_diff(left, right, key=None, unwrap=True):
        """
        Standard diff of two sets.

        Parameters:
        left        An iterable
        right       An iterable

        Return:
        tuple       (added, removed, matched)

        added       Set of items in right but not left
        removed     Set of items in left but not right
        matched     Set of items in both left and right.  This is
                    in the form of tuples with the matching item
                    from left and right
        """

        left_items = set(left)
        right_items = set(right)
        added_items = right_items - left_items
        removed_items = left_items - right_items

        # The problem here is the symbol from both policies are
        # needed to build each tuple in the matched items set.
        # Using the standard Python set intersection code will only result
        # in one object.
        #
        # This tuple-generating code creates lists from the sets, to sort them.
        # This should result in all of the symbols lining up.  If they don't,
        # this will break the caller.  This should work since there is no remapping.
        #
        # This has extra checking to make sure this assertion holds, to fail
        # instead of giving wrong results.  If there is a better way to,
        # ensure the items match up, please let me know how or submit a patch.
        matched_items = set()
        left_matched_items = sorted((left_items - removed_items), key=key)
        right_matched_items = sorted((right_items - added_items), key=key)
        assert len(left_matched_items) == len(right_matched_items), \
            "Matched items assertion failure (this is an SETools bug), {0} != {1}". \
            format(len(left_matched_items), len(right_matched_items))

        for left, right in zip(left_matched_items, right_matched_items):
            assert left == right, \
                "Matched items assertion failure (this is an SETools bug), {0} != {1}".format(
                    left, right)

            matched_items.add((left, right))

        if unwrap:
            return set(i.origin for i in added_items), \
                set(i.origin for i in removed_items), \
                set((left.origin, right.origin) for (left, right) in matched_items)
        else:
            return added_items, removed_items, matched_items


T = TypeVar("T", bound=PolicyObject)


class Wrapper(ABC, Generic[T]):

    """Abstract base class for policy object wrappers."""

    origin: T
    key: int

    __slots__ = ("origin", "key")

    def __init__(self, symbol: T) -> None:
        pass

    def __repr__(self):
        # pylint: disable=no-member
        return "<{0.__class__.__name__}(Wrapping {1})>".format(self, repr(self.origin))

    @abstractmethod
    def __hash__(self):
        pass

    @abstractmethod
    def __eq__(self, other):
        pass

    @abstractmethod
    def __lt__(self, other):
        pass

    def __ne__(self, other):
        return not self == other


S = TypeVar("S", bound=PolicySymbol)


# Pylint bug: https://github.com/PyCQA/pylint/issues/2822
class SymbolWrapper(Wrapper[S]):  # pylint: disable=unsubscriptable-object

    """
    General wrapper for policy symbols, e.g. types, roles
    to provide a diff-specific equality operation based
    on its name.
    """

    name: str

    __slots__ = ("name",)

    def __init__(self, symbol: S) -> None:
        self.origin = symbol
        self.name = str(symbol)
        self.key = hash(self.name)

    def __hash__(self):
        return self.key

    def __lt__(self, other):
        return self.name < other.name

    def __eq__(self, other):
        return self.name == other.name
