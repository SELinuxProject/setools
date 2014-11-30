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
from . import symbol
from . import qpol


class Common(symbol.PolicySymbol):

    """A common permission set."""

    def __contains__(self, other):
        return (other in (self.qpol_symbol.perm_iter(self.policy)))

    @property
    def perms(self):
        """The list of the common's permissions."""
        return set(self.qpol_symbol.perm_iter(self.policy))

    def statement(self):
        return "common {0}\n{{\n\t{1}\n}}".format(self, '\n\t'.join(self.perms))

    @property
    def value(self):
        """
        The value of the common.

        This is a low-level policy detail exposed so that commons can
        be sorted based on their policy declaration order instead of
        by their name.  This has no other use.

        Example usage: sorted(policy.commons(), key=lambda k: k.value)
        """
        return self.qpol_symbol.value(self.policy)


class NoCommon(Exception):

    """
    Exception when a class does not inherit a common permission set.
    """
    pass


class ObjClass(Common):

    """An object class."""

    @property
    def common(self):
        """
        The common that the object class inherits.

        Exceptions:
        NoCommon    The object class does not inherit a common.
        """

        try:
            return Common(self.policy, self.qpol_symbol.common(self.policy))
        except ValueError:
            raise NoCommon("{0} does not inherit a common.".format(self))

    def statement(self):
        stmt = "class {0}\n".format(self)

        try:
            stmt += "inherits {0}\n".format(self.common)
        except NoCommon:
            pass

        # a class that inherits may not have additional permissions
        perms = self.perms
        if len(perms) > 0:
            stmt += "{{\n\t{0}\n}}".format('\n\t'.join(perms))

        return stmt
