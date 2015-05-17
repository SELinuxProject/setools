# Copyright 2014, Tresys Technology, LLC
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
from . import exception
from . import symbol
from . import objclass
from . import qpol


def default_factory(policy, sym):
    """Factory generator for creating default_* statement objects."""

    # The low level policy groups default_* settings by object class.
    # Since each class can have up to four default_* statements,
    # this factory function is a generator which yields up to
    # four Default objects.

    if not isinstance(sym, qpol.qpol_default_object_t):
        raise NotImplementedError

    # qpol will essentially iterate over all classes
    # and emit None for classes that don't set a default
    if not sym.object_class(policy):
        raise exception.NoDefaults

    if sym.user_default(policy):
        yield UserDefault(policy, sym)

    if sym.role_default(policy):
        yield RoleDefault(policy, sym)

    if sym.type_default(policy):
        yield TypeDefault(policy, sym)

    if sym.range_default(policy):
        yield RangeDefault(policy, sym)


class Default(symbol.PolicySymbol):

    """Base class for default_* statements."""

    def __str__(self):
        raise NotImplementedError

    @property
    def object_class(self):
        """The object class."""
        return objclass.class_factory(self.policy, self.qpol_symbol.object_class(self.policy))

    @property
    def default(self):
        raise NotImplementedError

    def statement(self):
        return str(self)


class UserDefault(Default):

    """A default_user statement."""

    def __str__(self):
        return "default_user {0.object_class} {0.default};".format(self)

    @property
    def default(self):
        """The default user location (source/target)."""
        return self.qpol_symbol.user_default(self.policy)


class RoleDefault(Default):

    """A default_role statement."""

    def __str__(self):
        return "default_role {0.object_class} {0.default};".format(self)

    @property
    def default(self):
        """The default role location (source/target)."""
        return self.qpol_symbol.role_default(self.policy)


class TypeDefault(Default):

    """A default_type statement."""

    def __str__(self):
        return "default_type {0.object_class} {0.default};".format(self)

    @property
    def default(self):
        """The default type location (source/target)."""
        return self.qpol_symbol.type_default(self.policy)


class RangeDefault(Default):

    """A default_range statement."""

    def __str__(self):
        return "default_range {0.object_class} {0.default} {0.default_range};".format(self)

    @property
    def default(self):
        """The default range location (source/target)."""
        return self.qpol_symbol.range_default(self.policy).split()[0]

    @property
    def default_range(self):
        """The default range setting (low/high/low_high)."""
        return self.qpol_symbol.range_default(self.policy).split()[1]
