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
import symbol
import objclass
import qpol


class NoDefaults(symbol.InvalidSymbol):

    """Exception for classes that have no default_* statements."""
    pass


def default_factory(policy, symbol):
    """Factory generator for creating default objects."""

    # The low level policy groups default_* settings by object class.
    # Since each class can have up to four default_* statements,
    # this factory function is a generator which yields up to
    # four Default objects.

    if not isinstance(symbol, qpol.qpol_default_object_t):
        raise NotImplementedError

    # qpol will essentially iterate over all classes
    # and emit None for classes that don't set a default
    if not symbol.object_class(policy):
        raise NoDefaults

    if symbol.user_default(policy):
        yield UserDefault(policy, symbol)

    if symbol.role_default(policy):
        yield RoleDefault(policy, symbol)

    if symbol.type_default(policy):
        yield TypeDefault(policy, symbol)

    if symbol.range_default(policy):
        yield RangeDefault(policy, symbol)


class Default(symbol.PolicySymbol):

    """Abstract base class for default_* statements."""

    def __str__(self):
        raise NotImplementedError

    @property
    def object_class(self):
        return objclass.ObjClass(self.policy, self.qpol_symbol.object_class(self.policy))

    @property
    def default(self):
        raise NotImplementedError

    def statement(self):
        return str(self)


class UserDefault(Default):

    def __str__(self):
        return "default_user {0.object_class} {0.default};".format(self)

    @property
    def default(self):
        return self.qpol_symbol.user_default(self.policy)


class RoleDefault(Default):

    def __str__(self):
        return "default_role {0.object_class} {0.default};".format(self)

    @property
    def default(self):
        return self.qpol_symbol.role_default(self.policy)


class TypeDefault(Default):

    def __str__(self):
        return "default_type {0.object_class} {0.default};".format(self)

    @property
    def default(self):
        return self.qpol_symbol.type_default(self.policy)


class RangeDefault(Default):

    def __str__(self):
        return "default_range {0.object_class} {0.default} {0.default_range};".format(self)

    @property
    def default(self):
        return self.qpol_symbol.range_default(self.policy).split()[0]

    @property
    def default_range(self):
        return self.qpol_symbol.range_default(self.policy).split()[1]
