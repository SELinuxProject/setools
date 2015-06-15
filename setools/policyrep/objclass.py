# Copyright 2014-2015, Tresys Technology, LLC
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
from . import qpol


def common_factory(policy, name):
    """Factory function for creating common permission set objects."""

    if isinstance(name, Common):
        assert name.policy == policy
        return name
    elif isinstance(name, qpol.qpol_common_t):
        return Common(policy, name)

    try:
        return Common(policy, qpol.qpol_common_t(policy, str(name)))
    except ValueError:
        raise exception.InvalidCommon("{0} is not a valid common".format(name))


def class_factory(policy, name):
    """Factory function for creating object class objects."""

    if isinstance(name, ObjClass):
        assert name.policy == policy
        return name
    elif isinstance(name, qpol.qpol_class_t):
        return ObjClass(policy, name)

    try:
        return ObjClass(policy, qpol.qpol_class_t(policy, str(name)))
    except ValueError:
        raise exception.InvalidClass("{0} is not a valid object class".format(name))


class Common(symbol.PolicySymbol):

    """A common permission set."""

    def __contains__(self, other):
        return other in self.perms

    @property
    def perms(self):
        """The list of the common's permissions."""
        return set(self.qpol_symbol.perm_iter(self.policy))

    def statement(self):
        return "common {0}\n{{\n\t{1}\n}}".format(self, '\n\t'.join(self.perms))


class ObjClass(Common):

    """An object class."""

    def __contains__(self, other):
        try:
            if other in self.common.perms:
                return True
        except exception.NoCommon:
            pass

        return other in self.perms

    @property
    def common(self):
        """
        The common that the object class inherits.

        Exceptions:
        NoCommon    The object class does not inherit a common.
        """

        try:
            return common_factory(self.policy, self.qpol_symbol.common(self.policy))
        except ValueError:
            raise exception.NoCommon("{0} does not inherit a common.".format(self))

    def statement(self):
        stmt = "class {0}\n".format(self)

        try:
            stmt += "inherits {0}\n".format(self.common)
        except exception.NoCommon:
            pass

        # a class that inherits may not have additional permissions
        perms = self.perms
        if len(perms) > 0:
            stmt += "{{\n\t{0}\n}}".format('\n\t'.join(perms))

        return stmt
