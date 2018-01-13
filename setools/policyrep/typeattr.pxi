# Copyright 2014, Tresys Technology, LLC
# Copyright 2017, Chris PeBenito <pebenito@ieee.org>
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

#
# Type factory functions
#
cdef dict _type_cache = {}

cdef inline Type type_factory_lookup(SELinuxPolicy policy, str name, deref):
    """Factory function variant for constructing Type objects by name."""

    cdef const qpol_type_t *symbol

    if qpol_policy_get_type_by_name(policy.handle, name.encode(), &symbol):
        raise InvalidType("{0} is not a valid type".format(name))

    return type_factory(policy, symbol, deref)


cdef inline Type type_factory_iter(SELinuxPolicy policy, QpolIteratorItem symbol):
    """Factory function variant for iterating over Type objects."""
    return type_factory(policy, <const qpol_type_t *> symbol.obj, False)


cdef inline Type type_factory(SELinuxPolicy policy, const qpol_type_t *symbol, deref):
    """Factory function for creating Type objects."""
    cdef unsigned char isattr
    cdef unsigned char isalias
    cdef const char *name

    if qpol_type_get_isattr(policy.handle, symbol, &isattr):
        ex = LowLevelPolicyError("Error determining if type is an attribute: {}".format(
                                 strerror(errno)))
        ex.errno = errno
        raise ex

    if isattr:
        if qpol_type_get_name(policy.handle, symbol, &name):
            raise ValueError("The specified type is an attribute.")

        raise ValueError("{0} is an attribute".format(name))

    if qpol_type_get_isalias(policy.handle, symbol, &isalias):
        ex = LowLevelPolicyError("Error determining if type is an alias: {}".format(
                                 strerror(errno)))
        ex.errno = errno
        raise ex

    if isalias and not deref:
        if qpol_type_get_name(policy.handle, symbol, &name):
            raise ValueError("The specified type is an alias.")

        raise ValueError("{0} is an alias".format(name))

    try:
        return _type_cache[<uintptr_t>symbol]
    except KeyError:
        t = Type()
        t.policy = policy
        t.handle = symbol
        _type_cache[<uintptr_t>symbol] = t
        return t

#
# Attribute factory functions
#
cdef dict _typeattr_cache = {}

cdef inline TypeAttribute attribute_factory_lookup(SELinuxPolicy policy, str name):
    """Factory function variant for constructing TypeAttribute objects by name."""

    cdef const qpol_type_t *symbol
    if qpol_policy_get_type_by_name(policy.handle, name.encode(), &symbol):
        raise InvalidType("{0} is not a valid attribute".format(name))

    return attribute_factory(policy, symbol)


cdef inline TypeAttribute attribute_factory_iter(SELinuxPolicy policy, QpolIteratorItem symbol):
    """Factory function variant for iterating over TypeAttribute objects."""
    return attribute_factory(policy, <const qpol_type_t *> symbol.obj)


cdef inline TypeAttribute attribute_factory(SELinuxPolicy policy, const qpol_type_t *symbol):
    """Factory function for creating TypeAttribute objects."""

    cdef unsigned char isattr
    cdef const char *name

    if qpol_type_get_isattr(policy.handle, symbol, &isattr):
        ex = LowLevelPolicyError("Error determining if type is an attribute: {}".format(
                                 strerror(errno)))
        ex.errno = errno
        raise ex

    if not isattr:
        if qpol_type_get_name(policy.handle, symbol, &name):
            raise ValueError("The symbol is a type.")

        raise ValueError("{0} is a type".format(name))

    try:
        return _typeattr_cache[<uintptr_t>symbol]
    except KeyError:
        a = TypeAttribute()
        a.policy = policy
        a.handle = symbol
        _typeattr_cache[<uintptr_t>symbol] = a
        return a

#
# Type or Attribute factory functions
#
cdef inline BaseType type_or_attr_factory_lookup(SELinuxPolicy policy, str name, deref):
    """Factory function variant for constructing Type objects by name."""

    cdef const qpol_type_t *symbol
    cdef unsigned char isalias

    if qpol_policy_get_type_by_name(policy.handle, name.encode(), &symbol):
        raise InvalidType("{0} is not a valid type or type attribute".format(name))

    if qpol_type_get_isalias(policy.handle, symbol, &isalias):
        ex = LowLevelPolicyError("Error determining if type is an alias: {}".format(
                                 strerror(errno)))
        ex.errno = errno
        raise ex

    if isalias and not deref:
        raise ValueError("{0} is an alias.".format(name))

    return type_or_attr_factory(policy, symbol)


cdef inline BaseType type_or_attr_factory_iter(SELinuxPolicy policy, QpolIteratorItem symbol):
    """Factory function variant for iterating over Type or TypeAttribute objects."""
    return type_or_attr_factory(policy, <const qpol_type_t *> symbol.obj)


cdef inline BaseType type_or_attr_factory(SELinuxPolicy policy, const qpol_type_t *symbol):
    """Factory function for creating type or attribute objects."""

    cdef unsigned char i
    if qpol_type_get_isattr(policy.handle, symbol, &i):
        ex = LowLevelPolicyError("Error determining if type is an attribute: {}".format(
                                 strerror(errno)))
        ex.errno = errno
        raise ex

    if i:
        return attribute_factory(policy, symbol)
    else:
        return type_factory(policy, symbol, False)


#
# Classes
#
cdef class BaseType(PolicySymbol):

    """Type/attribute base class."""

    cdef const qpol_type_t *handle

    def __str__(self):
        cdef const char *name

        if qpol_type_get_name(self.policy.handle, self.handle, &name):
            ex = LowLevelPolicyError("Error reading type name: {}".format(strerror(errno)))
            ex.errno = errno
            raise ex

        return intern(name)

    def _eq(self, BaseType other):
        """Low-level equality check (C pointers)."""
        return self.handle == other.handle

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


cdef class Type(BaseType):

    """A type."""

    def __deepcopy__(self, memo):
        # shallow copy as all of the members are immutable
        newobj = type_factory(self.policy, self.handle, False)
        memo[id(self)] = newobj
        return newobj

    def __getstate__(self):
        return (self.policy, self._pickle())

    def __setstate__(self, state):
        self.policy = state[0]
        self._unpickle(state[1])

    cdef bytes _pickle(self):
        return <bytes>(<char *>self.handle)

    cdef _unpickle(self, bytes handle):
        memcpy(&self.handle, <char *>handle, sizeof(qpol_type_t*))

    @property
    def ispermissive(self):
        """(T/F) the type is permissive."""
        cdef unsigned char i
        if qpol_type_get_ispermissive(self.policy.handle, self.handle, &i):
            ex = LowLevelPolicyError("Error determining if type is permissive: {}".format(
                                     strerror(errno)))
            ex.errno = errno
            raise ex

        return bool(i)

    def expand(self):
        """Generator that expands this into its member types."""
        yield self

    def attributes(self):
        """Generator that yields all attributes for this type."""
        cdef qpol_iterator_t *iter
        if qpol_type_get_attr_iter(self.policy.handle, self.handle, &iter) < 0:
            ex = LowLevelPolicyError("Error reading type attributes: {}".format(strerror(errno)))
            ex.errno = errno
            raise ex

        return qpol_iterator_factory(self.policy, iter, attribute_factory_iter)

    def aliases(self):
        """Generator that yields all aliases for this type."""
        cdef qpol_iterator_t *iter
        if qpol_type_get_alias_iter(self.policy.handle, self.handle, &iter):
            raise MemoryError

        return qpol_iterator_factory(self.policy, iter, string_factory_iter)

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


cdef class TypeAttribute(BaseType):

    """A type attribute."""

    def __contains__(self, other):
        for type_ in self.expand():
            if other == type_:
                return True

        return False

    def expand(self):
        """Generator that expands this attribute into its member types."""
        cdef qpol_iterator_t *iter
        if qpol_type_get_type_iter(self.policy.handle, self.handle, &iter) < 0:
            raise MemoryError

        return qpol_iterator_factory(self.policy, iter, type_factory_iter)

    def attributes(self):
        """Generator that yields all attributes for this type."""
        raise SymbolUseError("{0} is an attribute, thus does not have attributes.".format(self))

    def aliases(self):
        """Generator that yields all aliases for this type."""
        raise SymbolUseError("{0} is an attribute, thus does not have aliases.".format(self))

    @property
    def ispermissive(self):
        """(T/F) the type is permissive."""
        raise SymbolUseError("{0} is an attribute, thus cannot be permissive.".format(self))

    def statement(self):
        return "attribute {0};".format(self)
