# SPDX-License-Identifier: GPL-2.0-only
# pylint: disable=attribute-defined-outside-init

from unittest.mock import Mock

import pytest
import setools


class SortableMock(Mock):

    """Mock class that can be sorted."""

    def __lt__(self, other):
        return self.name < other.name

    def __repr__(self):
        return f"<{self.__class__} name={self.name}>"


@pytest.fixture
def mock_policy() -> Mock:
    """Build a mock policy."""
    foo_bool = SortableMock(setools.Boolean)
    foo_bool.name = "foo_bool"
    bar_bool = SortableMock(setools.Boolean)
    bar_bool.name = "bar_bool"

    common = SortableMock(setools.Common)
    common.name = "common_perm_set"
    common.perms = frozenset(("common_perm",))

    foo_class = SortableMock(setools.ObjClass)
    foo_class.name = "foo_class"
    foo_class.perms = frozenset(("foo_perm1", "foo_perm2"))
    foo_class.common = common
    bar_class = SortableMock(setools.ObjClass)
    bar_class.name = "bar_class"
    bar_class.perms = frozenset(("bar_perm1", "bar_perm2"))
    bar_class.common = common

    foo_t = SortableMock(setools.Type)
    foo_t.name = "foo_t"
    bar_t = SortableMock(setools.Type)
    bar_t.name = "bar_t"

    fooattr = SortableMock(setools.TypeAttribute)
    fooattr.name = "foo_type"
    barattr = SortableMock(setools.TypeAttribute)
    barattr.name = "bar_type"

    foo_r = SortableMock(setools.Role)
    foo_r.name = "foo_r"
    bar_r = SortableMock(setools.Role)
    bar_r.name = "bar_r"

    foo_u = SortableMock(setools.User)
    foo_u.name = "foo_u"
    bar_u = SortableMock(setools.User)
    bar_u.name = "bar_u"

    policy = Mock(setools.SELinuxPolicy)
    policy.bools.return_value = (foo_bool, bar_bool)
    policy.classes.return_value = (foo_class, bar_class)
    policy.roles.return_value = (foo_r, bar_r)
    policy.types.return_value = (foo_t, bar_t)
    policy.typeattributes.return_value = (fooattr, barattr)
    policy.users.return_value = (foo_u, bar_u)
    return policy


@pytest.fixture
def mock_query(mock_policy) -> Mock:
    """Build a mock query with mocked policy."""
    query = Mock(setools.PolicyQuery)
    query.policy = mock_policy
    return query
