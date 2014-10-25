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
import qpol
import symbol
import user
import role
import typeattr
import mls


class Context(symbol.PolicySymbol):

    """A SELinux security context/security attribute."""

    def __str__(self):
        try:
            return "{0.user}:{0.role}:{0.type_}:{0.mls}".format(self)
        except mls.MLSDisabled:
            return "{0.user}:{0.role}:{0.type_}".format(self)

    @property
    def user(self):
        """The user portion of the context."""
        return user.User(self.policy, self.qpol_symbol.user(self.policy))

    @property
    def role(self):
        """The role portion of the context."""
        return role.Role(self.policy, self.qpol_symbol.role(self.policy))

    @property
    def type_(self):
        """The type portion of the context."""
        return typeattr.TypeAttr(self.policy, self.qpol_symbol.type_(self.policy))

    @property
    def mls(self):
        """The MLS portion (range) of the context."""

        # without this check, qpol will segfault on MLS-disabled policies
        if self.policy.has_capability(qpol.QPOL_CAP_MLS):
            return mls.MLSRange(self.policy, self.qpol_symbol.range(self.policy))
        else:
            raise mls.MLSDisabled("MLS is disabled, the context has no range.")
