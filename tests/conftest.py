# SPDX-License-Identifier: GPL-2.0-only
# pylint: disable=attribute-defined-outside-init
import os
from collections.abc import Iterable
from contextlib import suppress
import subprocess
import tempfile
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
def mock_role():
    generated_roles: dict[str, setools.Role] = {}

    def _factory(name: str, /, *, types: frozenset[setools.Type] | None = None) -> setools.Role:
        """Factory function for Role objects."""
        with suppress(KeyError):
            return generated_roles[name]

        role = SortableMock(setools.Role)
        role.name = name

        if types is not None:
            role.types.return_value = types

        generated_roles[name] = role
        return role

    return _factory


@pytest.fixture
def mock_user(mock_role):
    generated_users: dict[str, setools.User] = {}

    def _factory(name: str, /, *, roles: frozenset[setools.Role] | None = None,
                 level: setools.Level | None = None,
                 range_: setools.Range | None = None) -> setools.User:
        """Factory function for User objects."""
        with suppress(KeyError):
            return generated_users[name]

        assert (level and range_) or (not level and not range_)

        user = SortableMock(setools.User)
        user.name = name

        if roles is not None:
            # inject object_r, like the compiler does
            full_roles = {mock_role("object_r"), *roles}
            user.roles.return_value = frozenset(full_roles)

        if level:
            user._level = level
            user._range = range_
        else:
            user._level = None
            user._range = None

        generated_users[name] = user
        return user

    return _factory


@pytest.fixture
def mock_policy(mock_user, mock_role) -> setools.SELinuxPolicy:
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

    foo_r = mock_role("foo_r", types=frozenset((foo_t,)))
    bar_r = mock_role("bar_r", types=frozenset((bar_t,)))

    foo_u = mock_user("foo_u", roles=frozenset((foo_r,)))
    bar_u = mock_user("bar_u", roles=frozenset((bar_r,)))

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
def mock_query(mock_policy) -> setools.PolicyQuery:
    """Build a mock query with mocked policy."""
    query = Mock(setools.PolicyQuery)
    query.policy = mock_policy
    return query


@pytest.fixture(scope="class")
def compiled_policy(request: pytest.FixtureRequest) -> Iterable[setools.SELinuxPolicy]:
    """Build a compiled policy."""
    marker = request.node.get_closest_marker("obj_args")
    args = marker.args if marker else ()
    kwargs = marker.kwargs if marker else {}

    source_file = args[0]

    if "USERSPACE_SRC" in os.environ:
        command = [os.environ['USERSPACE_SRC'] + "/checkpolicy/checkpolicy"]
    elif "CHECKPOLICY" in os.environ:
        command = [os.environ['CHECKPOLICY']]
    else:
        command = ["/usr/bin/checkpolicy"]

    if kwargs.get("mls", True):
        command.append("-M")

    if kwargs.get("xen", False):
        command.extend(["-t", "xen", "-c", "30"])

    with tempfile.NamedTemporaryFile("w") as fd:
        command.extend(["-o", fd.name, "-U", "reject", source_file])

        with open(os.devnull, "w+b") as null:
            subprocess.check_call(command, stdout=null, shell=False, close_fds=True)

        yield setools.SELinuxPolicy(fd.name)
