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
from . import qpol
from . import symbol
from . import typeattr


class Role(symbol.PolicySymbol):

    """A role."""

    def expand(self):
        """
        Generator that expands this attribute into its member roles.
        If this is a role, the role itself will be yielded.
        """
        # Role attributes are already expanded in the binary policy
        yield self

    @property
    def isattr(self):
        """(T/F) this is an attribute."""
        # Role attributes are already expanded in the binary policy
        return False

    def types(self):
        """Generator which yields the role's set of types."""

        titer = self.qpol_symbol.type_iter(self.policy)
        while not titer.isend():
            yield typeattr.TypeAttr(
                self.policy, qpol.qpol_type_from_void(titer.item()))
            titer.next_()

    def statement(self):
        types = list(str(t) for t in self.types())
        stmt = "role {0}".format(self)
        if (len(types) > 1):
            stmt += " types {{ {0} }};".format(' '.join(types))
        else:
            try:
                stmt += " types {0};".format(types[0])
            except IndexError:
                stmt += ";"

        return stmt
