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
from . import qpol
from . import symbol
from . import user
from . import role
from . import typeattr
from . import mls


def context_factory(policy, name):
    """Factory function for creating context objects."""

    if not isinstance(name, qpol.qpol_context_t):
        raise TypeError("Contexts cannot be looked-up.")

    return Context(policy, name)


class Context(symbol.PolicySymbol):

    """A SELinux security context/security attribute."""

    def __str__(self):
        try:
            return "{0.user}:{0.role}:{0.type_}:{0.range_}".format(self)
        except exception.MLSDisabled:
            return "{0.user}:{0.role}:{0.type_}".format(self)

    @property
    def user(self):
        """The user portion of the context."""
        return user.user_factory(self.policy, self.qpol_symbol.user(self.policy))

    @property
    def role(self):
        """The role portion of the context."""
        return role.role_factory(self.policy, self.qpol_symbol.role(self.policy))

    @property
    def type_(self):
        """The type portion of the context."""
        return typeattr.type_factory(self.policy, self.qpol_symbol.type_(self.policy))

    @property
    def range_(self):
        """The MLS range of the context."""
        return mls.range_factory(self.policy, self.qpol_symbol.range(self.policy))

    def statement(self):
        raise exception.NoStatement
