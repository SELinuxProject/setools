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


class Role(symbol.PolicySymbol):

    """A role."""

    def expand(self):
        """
        Generator that expands this attribute into its member roles.
        If this	is a role, the role itself will be yielded.
        """
        # Role attributes are already expanded in the binary policy
        yield self

    @property
    def isattr(self):
        """(T/F) this is an attribute."""
        # Role attributes are already expanded in the binary policy
        return False
