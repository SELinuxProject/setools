# SPDX-License-Identifier: GPL-2.0-only
from unittest.mock import Mock

from setools import SELinuxPolicy
from setools.policyrep import (Boolean, Common, ObjClass, Type, TypeAttribute)
from setools.query import PolicyQuery


class SortableMock(Mock):

    def __lt__(self, other):
        return self.name < other.name

    def __repr__(self):
        return f"<{self.__class__} name={self.name}>"


def _build_mock_policy() -> Mock:
    """Build a mock policy."""
    foo_bool = SortableMock(Boolean)
    foo_bool.name = "foo_bool"
    bar_bool = SortableMock(Boolean)
    bar_bool.name = "bar_bool"

    common = SortableMock(Common)
    common.name = "common_perm_set"
    common.perms = frozenset(("common_perm",))

    foo_class = SortableMock(ObjClass)
    foo_class.name = "foo_class"
    foo_class.perms = frozenset(("foo_perm1", "foo_perm2"))
    foo_class.common = common
    bar_class = SortableMock(ObjClass)
    bar_class.name = "bar_class"
    bar_class.perms = frozenset(("bar_perm1", "bar_perm2"))
    bar_class.common = common

    foo_t = SortableMock(Type)
    foo_t.name = "foo_t"
    bar_t = SortableMock(Type)
    bar_t.name = "bar_t"

    fooattr = SortableMock(TypeAttribute)
    fooattr.name = "foo_type"
    barattr = SortableMock(TypeAttribute)
    barattr.name = "bar_type"

    policy = Mock(SELinuxPolicy)
    policy.bools.return_value = (foo_bool, bar_bool)
    policy.classes.return_value = (foo_class, bar_class)
    policy.types.return_value = (foo_t, bar_t)
    policy.typeattributes.return_value = (fooattr, barattr)
    return policy


def _build_mock_query() -> Mock:
    """Build a mock query with mocked policy."""
    mock_query = Mock(PolicyQuery)
    mock_query.policy = _build_mock_policy()
    return mock_query
