# Copyright 2014, 2016 Tresys Technology, LLC
# Copyright 2016, Chris PeBenito <pebenito@ieee.org>
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
from .util import PolicyEnum


def validate_ruletype(t):
    """Validate default_* rule types."""
    try:
        return DefaultRuletype.lookup(t)
    except KeyError:
        raise exception.InvalidDefaultType("{0} is not a valid default_*  rule type.".format(t))


def validate_default_value(default):
    try:
        return DefaultValue.lookup(default)
    except KeyError:
        raise exception.InvalidDefaultValue("{0} is not a valid default_* value.".format(default))


def validate_default_range(default):
    try:
        return DefaultRangeValue.lookup(default)
    except KeyError:
        raise exception.InvalidDefaultRange("{0} is not a valid default_* range.".format(default))


class DefaultRuletype(PolicyEnum):

    """Enumeration of default rule types."""
    default_user = 1
    default_role = 2
    default_type = 3
    default_range = 4


class DefaultValue(PolicyEnum):

    """Enumeration of default values."""
    source = 1
    target = 2


class DefaultRangeValue(PolicyEnum):

    """Enumeration of default range values."""
    low = 1
    high = 2
    low_high = 3


def default_factory(policy, sym):
    """Factory generator for creating default_* statement objects."""

    # The low level policy groups default_* settings by object class.
    # Since each class can have up to four default_* statements,
    # this factory function is a generator which yields up to
    # four Default objects.

    if not isinstance(sym, qpol.qpol_default_object_t):
        raise NotImplementedError

    # qpol will essentially iterate over all classes
    # and emit None for classes that don't set a default.
    # Because of all of this processing, extract almost
    # all of the information out of the qpol representation.
    # (we have to determine almost all of it anyway)
    if not sym.object_class(policy):
        raise exception.NoDefaults

    user = sym.user_default(policy)
    role = sym.role_default(policy)
    type_ = sym.type_default(policy)
    range_ = sym.range_default(policy)

    if user:
        obj = Default(policy, sym)
        obj.ruletype = DefaultRuletype.default_user
        obj.default = DefaultValue[user]
        yield obj

    if role:
        obj = Default(policy, sym)
        obj.ruletype = DefaultRuletype.default_role
        obj.default = DefaultValue[role]
        yield obj

    if type_:
        obj = Default(policy, sym)
        obj.ruletype = DefaultRuletype.default_type
        obj.default = DefaultValue[type_]
        yield obj

    if range_:
        # range_ is something like "source low_high"
        rng = range_.split()
        obj = RangeDefault(policy, sym)
        obj.ruletype = DefaultRuletype.default_range
        obj.default = DefaultValue[rng[0]]
        obj.default_range = DefaultRangeValue[rng[1]]
        yield obj


class Default(symbol.PolicySymbol):

    """Base class for default_* statements."""

    def __str__(self):
        return "{0.ruletype} {0.tclass} {0.default};".format(self)

    def __hash__(self):
        return hash("{0.ruletype}|{0.tclass}".format(self))

    @property
    def tclass(self):
        """The object class."""
        return objclass.class_factory(self.policy, self.qpol_symbol.object_class(self.policy))

    def statement(self):
        return str(self)


class RangeDefault(Default):

    """A default_range statement."""

    default_range = None

    def __str__(self):
        return "{0.ruletype} {0.tclass} {0.default} {0.default_range};".format(self)
