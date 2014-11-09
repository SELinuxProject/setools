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


class InvalidType(symbol.InvalidSymbol):

    """Exception for invalid types and attributes."""
    pass


class TypeAttr(symbol.PolicySymbol):

    """
    A type or attribute.

    Parameters:
    policy          The low-level policy.
    symbol          The low-level type/attribute reference or a
                    string to look up a type.

    Exceptions:
    InvalidType     The specified type/attribute name does not exist in
                    the policy.
    """

    def __init__(self, policy, symbol):
        self.policy = policy

        if isinstance(symbol, str):
            try:
                self.qpol_symbol = qpol.qpol_type_t(policy, symbol)
            except ValueError:
                raise InvalidType(
                    "{0} is not a valid type or attribute".format(symbol))
        else:
            self.qpol_symbol = symbol

    @property
    def ispermissive(self):
        """(T/F) the type is permissive."""
        return self.qpol_symbol.ispermissive(self.policy)

    @property
    def isattr(self):
        """(T/F) this is an attribute."""
        return self.qpol_symbol.isattr(self.policy)

    @property
    def isalias(self):
        """(T/F) this is an alias."""
        return self.qpol_symbol.isalias(self.policy)

    def expand(self):
        """
        Generator that expands this attribute into its member types.
        If this is a type, the type itself will be yielded.
        """
        # if this is not an attribute, yield only the type itself
        if not self.isattr:
            yield self
        else:
            for type_ in self.qpol_symbol.type_iter(self.policy):
                yield TypeAttr(self.policy, type_)

    def attributes(self):
        """Generator that yields all attributes for this type."""
        if self.isattr:
            raise TypeError(
                "{0} is an attribute, thus does not have attributes.".format(self))

        for attr in self.qpol_symbol.attr_iter(self.policy):
            yield TypeAttr(self.policy, attr)

    def aliases(self):
        """Generator that yields all aliases for this type."""
        if self.isattr:
            raise TypeError(
                "{0} is an attribute, thus does not have aliases.".format(self))

        for alias in self.qpol_symbol.alias_iter(self.policy):
            yield alias

    def statement(self):
        if self.isattr:
            return "attribute {0};".format(self)
        else:
            attrs = list(self.attributes())
            aliases = list(self.aliases())
            stmt = "type {0}".format(self)
            if aliases:
                if len(aliases) > 1:
                    stmt += " alias {{ {0} }}".format(' '.join(aliases))
                else:
                    stmt += " alias {0}".format(aliases[0])
            for a in attrs:
                stmt += ", {0}".format(a)
            stmt += ";"
            return stmt
