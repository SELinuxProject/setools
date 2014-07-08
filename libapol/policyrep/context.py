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
import setools.qpol as qpol

import symbol
import user
import role
import typeattr
import mls


class Context(symbol.PolicySymbol):

    """A SELinux security context/security attribute."""

    def __str__(self):
        ctx = "{0.user}:{0.role}:{0.type_}".format(self)

        # TODO qpol doesn't currently export a way to check if
        # MLS is enabled.  It also will segfault if we try to get
        # a range on a policy w/o MLS
        # if mls:
        #	ctx += ":{0}".format(self.mls)
        return ctx

    @property
    def user(self):
        """The user portion of the context."""
        return user.User(self.policy, self.qpol_symbol.get_user(self.policy))

    @property
    def role(self):
        """The role portion of the context."""
        return role.Role(self.policy, self.qpol_symbol.get_role(self.policy))

    @property
    def type_(self):
        """The type portion of the context."""
        return typeattr.TypeAttr(self.policy, self.qpol_symbol.get_type(self.policy))

    @property
    def mls(self):
        """The MLS portion (range) of the context."""
        return mls.MLSRange(self.policy, self.qpol_symbol.get_range(self.policy))
