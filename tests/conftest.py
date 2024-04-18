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
def mock_type():
    generated_types: dict[str, setools.Type] = {}

    def _factory(name: str, attrs: Iterable[setools.TypeAttribute] | None = None,
                 alias: Iterable[str] | None = None, perm: bool = False) -> setools.Type:
        """Factory function for Type objects."""
        with suppress(KeyError):
            return generated_types[name]

        type_ = SortableMock(setools.Type)
        type_.name = name
        type_.ispermissive = perm
        type_.attributes.return_value = attrs if attrs is not None else ()
        type_.aliases.return_value = alias if alias is not None else ()
        generated_types[name] = type_
        return type_

    return _factory


@pytest.fixture
def mock_typeattr():
    generated_attrs: dict[str, setools.TypeAttribute] = {}

    def _factory(name: str, types: Iterable[setools.Type] | None = None) -> setools.TypeAttribute:
        """Factory function for TypeAttribute objects, using a mock qpol object."""
        attr = SortableMock(setools.TypeAttribute)
        attr.name = name
        attr.expand.return_value = types if types is not None else ()
        generated_attrs[name] = attr
        return attr

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
def mock_policy(mock_type, mock_typeattr, mock_user, mock_role) -> setools.SELinuxPolicy:
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

    fooattr = mock_typeattr("foo_type")
    barattr = mock_typeattr("bar_type")

    foo_t = mock_type("foo_t", attrs=(fooattr,))
    fooattr.expand.return_value = (foo_t,)
    bar_t = mock_type("bar_t", attrs=(barattr,))
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


def _do_compile(source_file: str, output_file: str, /, *, mls: bool = True,
                xen: bool = False) -> setools.SELinuxPolicy:
    """
    Compile the specified source policy.  Checkpolicy is
    assumed to be /usr/bin/checkpolicy.  Otherwise the path
    must be specified in the CHECKPOLICY environment variable.

    Return:
    A SELinuxPolicy object.
    """
    user_src = os.getenv("USERSPACE_SRC")
    checkpol = os.getenv("CHECKPOLICY")

    if user_src:
        command = [user_src + "/checkpolicy/checkpolicy"]
    elif checkpol:
        command = [checkpol]
    else:
        command = ["/usr/bin/checkpolicy"]

    if mls:
        command.append("-M")

    if xen:
        command.extend(["-t", "xen", "-c", "30"])

    command.extend(["-o", output_file, "-U", "reject", source_file])

    with open(os.devnull, "w") as null:
        subprocess.check_call(command, stdout=null, shell=False, close_fds=True)

    return setools.SELinuxPolicy(output_file)


@pytest.fixture(scope="class")
def compiled_policy(request: pytest.FixtureRequest) -> Iterable[setools.SELinuxPolicy]:
    """Build a compiled policy."""
    marker = request.node.get_closest_marker("obj_args")
    args = marker.args if marker else ()
    kwargs = marker.kwargs if marker else {}

    source_file = args[0]

    with tempfile.NamedTemporaryFile("w") as fd:
        yield _do_compile(source_file, fd.name, mls=kwargs.get("mls", True),
                          xen=kwargs.get("xen", False))


@pytest.fixture(scope="class")
def policy_pair(request: pytest.FixtureRequest) -> \
        Iterable[tuple[setools.SELinuxPolicy, setools.SELinuxPolicy]]:
    """Build a compiled policy."""
    marker = request.node.get_closest_marker("obj_args")
    args = marker.args if marker else ()
    kwargs = marker.kwargs if marker else {}

    source_file_left = args[0]
    source_file_right = args[1]

    with tempfile.NamedTemporaryFile("w") as fd_left:
        with tempfile.NamedTemporaryFile("w") as fd_right:
            left = _do_compile(source_file_left, fd_left.name,
                               mls=kwargs.get("mls_left", True),
                               xen=kwargs.get("xen_left", False))
            right = _do_compile(source_file_right, fd_right.name,
                                mls=kwargs.get("mls_right", True),
                                xen=kwargs.get("xen_right", False))
            yield left, right
