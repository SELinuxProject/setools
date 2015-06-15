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
from . import exception
from . import qpol
from . import symbol


def _symbol_lookup(qpol_policy, name):
    """Look up the low-level qpol policy reference"""
    if isinstance(name, qpol.qpol_type_t):
        return name

    try:
        return qpol.qpol_type_t(qpol_policy, str(name))
    except ValueError:
        raise exception.InvalidType("{0} is not a valid type/attribute".format(name))


def attribute_factory(qpol_policy, name):
    """Factory function for creating attribute objects."""

    if isinstance(name, TypeAttribute):
        assert name.policy == qpol_policy
        return name

    qpol_symbol = _symbol_lookup(qpol_policy, name)

    if not qpol_symbol.isattr(qpol_policy):
        raise TypeError("{0} is a type".format(qpol_symbol.name(qpol_policy)))

    return TypeAttribute(qpol_policy, qpol_symbol)


def type_factory(qpol_policy, name, deref=False):
    """Factory function for creating type objects."""

    if isinstance(name, Type):
        assert name.policy == qpol_policy
        return name

    qpol_symbol = _symbol_lookup(qpol_policy, name)

    if qpol_symbol.isattr(qpol_policy):
        raise TypeError("{0} is an attribute".format(qpol_symbol.name(qpol_policy)))
    elif qpol_symbol.isalias(qpol_policy) and not deref:
        raise TypeError("{0} is an alias.".format(qpol_symbol.name(qpol_policy)))

    return Type(qpol_policy, qpol_symbol)


def type_or_attr_factory(qpol_policy, name, deref=False):
    """Factory function for creating type or attribute objects."""

    if isinstance(name, (Type, TypeAttribute)):
        assert name.policy == qpol_policy
        return name

    qpol_symbol = _symbol_lookup(qpol_policy, name)

    if qpol_symbol.isalias(qpol_policy) and not deref:
        raise TypeError("{0} is an alias.".format(qpol_symbol.name(qpol_policy)))

    if qpol_symbol.isattr(qpol_policy):
        return TypeAttribute(qpol_policy, qpol_symbol)
    else:
        return Type(qpol_policy, qpol_symbol)


class BaseType(symbol.PolicySymbol):

    """Type/attribute base class."""

    @property
    def ispermissive(self):
        raise NotImplementedError

    def expand(self):
        """Generator that expands this attribute into its member types."""
        raise NotImplementedError

    def attributes(self):
        """Generator that yields all attributes for this type."""
        raise NotImplementedError

    def aliases(self):
        """Generator that yields all aliases for this type."""
        raise NotImplementedError


class Type(BaseType):

    """A type."""

    @property
    def ispermissive(self):
        """(T/F) the type is permissive."""
        return self.qpol_symbol.ispermissive(self.policy)

    def expand(self):
        """Generator that expands this into its member types."""
        yield self

    def attributes(self):
        """Generator that yields all attributes for this type."""
        for attr in self.qpol_symbol.attr_iter(self.policy):
            yield attribute_factory(self.policy, attr)

    def aliases(self):
        """Generator that yields all aliases for this type."""
        for alias in self.qpol_symbol.alias_iter(self.policy):
            yield alias

    def statement(self):
        attrs = list(self.attributes())
        aliases = list(self.aliases())
        stmt = "type {0}".format(self)
        if aliases:
            if len(aliases) > 1:
                stmt += " alias {{ {0} }}".format(' '.join(aliases))
            else:
                stmt += " alias {0}".format(aliases[0])
        for attr in attrs:
            stmt += ", {0}".format(attr)
        stmt += ";"
        return stmt


class TypeAttribute(BaseType):

    """An attribute."""

    def __contains__(self, other):
        for type_ in self.expand():
            if other == type_:
                return True

        return False

    def expand(self):
        """Generator that expands this attribute into its member types."""
        for type_ in self.qpol_symbol.type_iter(self.policy):
            yield type_factory(self.policy, type_)

    def attributes(self):
        """Generator that yields all attributes for this type."""
        raise TypeError("{0} is an attribute, thus does not have attributes.".format(self))

    def aliases(self):
        """Generator that yields all aliases for this type."""
        raise TypeError("{0} is an attribute, thus does not have aliases.".format(self))

    @property
    def ispermissive(self):
        """(T/F) the type is permissive."""
        raise TypeError("{0} is an attribute, thus cannot be permissive.".format(self))

    def statement(self):
        return "attribute {0};".format(self)
