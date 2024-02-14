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

    fooattr = SortableMock(setools.TypeAttribute)
    fooattr.name = "foo_type"
    barattr = SortableMock(setools.TypeAttribute)
    barattr.name = "bar_type"

    foo_t = SortableMock(setools.Type)
    foo_t.name = "foo_t"
    foo_t.attributes.return_value = (fooattr,)
    fooattr.expand.return_value = (foo_t,)
    bar_t = SortableMock(setools.Type)
    bar_t.name = "bar_t"
    bar_t.attributes.return_value = (barattr,)
    barattr.expand.return_value = (bar_t,)

    foo_r = SortableMock(setools.Role)
    foo_r.name = "foo_r"
    foo_r.types.return_value = (foo_t,)
    bar_r = SortableMock(setools.Role)
    bar_r.name = "bar_r"
    bar_r.types.return_value = (bar_t,)

    foo_u = SortableMock(setools.User)
    foo_u.name = "foo_u"
    foo_u.roles.return_value = (foo_r,)
    bar_u = SortableMock(setools.User)
    bar_u.name = "bar_u"
    bar_u.roles.return_value = (bar_r,)

    foo_cat = SortableMock(setools.Category)
    foo_cat.name = "foo_cat"
    foo_cat.aliases.return_value = ("foo_cat_alias",)
    bar_cat = SortableMock(setools.Category)
    bar_cat.name = "bar_cat"
    bar_cat.aliases.return_value = ("bar_cat_alias",)

    foo_sen = SortableMock(setools.Sensitivity)
    foo_sen.name = "foo_sen"
    foo_sen.aliases.return_value = ("foo_sen_alias",)
    bar_sen = SortableMock(setools.Sensitivity)
    bar_sen.name = "bar_sen"
    bar_sen.aliases.return_value = ("bar_sen_alias",)

    policy = Mock(setools.SELinuxPolicy)
    policy.mls = False
    policy.bools.return_value = (foo_bool, bar_bool)
    policy.categories.return_value = (foo_cat, bar_cat)
    policy.classes.return_value = (foo_class, bar_class)
    policy.commons.return_value = (common,)
    policy.roles.return_value = (foo_r, bar_r)
    policy.sensitivities.return_value = (foo_sen, bar_sen)
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
