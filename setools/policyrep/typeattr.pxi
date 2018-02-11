# Copyright 2014, Tresys Technology, LLC
# Copyright 2017-2018, Chris PeBenito <pebenito@ieee.org>
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
import warnings

#
# Cache objects
#
cdef dict _type_cache = {}
cdef dict _typeattr_cache = {}


#
# Type or attribute factory function
#
cdef type_or_attr_factory(SELinuxPolicy policy, sepol.type_datum_t *symbol):
    """Factory function for creating type or attribute objects."""
    cdef sepol.type_datum_t *handle

    if symbol.flavor == sepol.TYPE_ATTRIB:
        return TypeAttribute.factory(policy, symbol)
    else:
        return Type.factory(policy, symbol)


#
# Classes
#
cdef class BaseType(PolicySymbol):

    """Type/attribute base class."""

    cdef sepol.type_datum_t *handle

    def __str__(self):
        return intern(self.policy.handle.p.p.sym_val_to_name[sepol.SYM_TYPES][self.handle.s.value - 1])

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

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.type_datum_t *symbol):
        """Factory function for creating Type objects."""
        if symbol.flavor != sepol.TYPE_TYPE:
            raise ValueError("{0} is not a type".format(
                policy.handle.p.p.sym_val_to_name[sepol.SYM_TYPES][symbol.s.value - 1]))

        try:
            return _type_cache[<uintptr_t>symbol]
        except KeyError:
            t = Type()
            t.policy = policy
            t.handle = symbol
            _type_cache[<uintptr_t>symbol] = t
            return t

    def __deepcopy__(self, memo):
        # shallow copy as all of the members are immutable
        newobj = Type.factory(self.policy, self.handle)
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
        memcpy(&self.handle, <char *>handle, sizeof(sepol.type_datum_t*))

    @property
    def ispermissive(self):
        """(T/F) the type is permissive."""
        return <bint> ebitmap_get_bit(&self.policy.handle.p.p.permissive_map, self.handle.s.value)

    def expand(self):
        """Generator that expands this into its member types."""
        yield self

    def attributes(self):
        """Generator that yields all attributes for this type."""
        return TypeAttributeEbitmapIterator.factory(self.policy, &self.handle.types)

    def aliases(self):
        """Generator that yields all aliases for this type."""
        return TypeAliasHashtabIterator.factory(self.policy, &self.policy.handle.p.p.symtab[sepol.SYM_TYPES].table, self)

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

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.type_datum_t *symbol):
        """Factory function for creating TypeAttribute objects."""
        if symbol.flavor != sepol.TYPE_ATTRIB:
            raise ValueError("{0} is not an attribute".format(
                policy.handle.p.p.sym_val_to_name[sepol.SYM_TYPES][symbol.s.value - 1]))

        try:
            return _typeattr_cache[<uintptr_t>symbol]
        except KeyError:
            t = TypeAttribute()
            t.policy = policy
            t.handle = symbol
            _typeattr_cache[<uintptr_t>symbol] = t
            return t

    def __contains__(self, other):
        for type_ in self.expand():
            if other == type_:
                return True

        return False

    def expand(self):
        """Generator that expands this attribute into its member types."""
        return TypeEbitmapIterator.factory(self.policy, &self.handle.types)

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


#
# Hash Table Iterator Classes
#
cdef inline type_is_alias(sepol.type_datum_t *datum):
    """Determine if the type datum is an alias."""
    return (datum.primary == 0 and datum.flavor == sepol.TYPE_TYPE) \
            or datum.flavor == sepol.TYPE_ALIAS


cdef class TypeHashtabIterator(HashtabIterator):

    """Iterate over types in the policy."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.hashtab_t *table):
        """Factory function for creating Role iterators."""
        i = TypeHashtabIterator()
        i.policy = policy
        i.table = table
        i.reset()
        return i

    def __next__(self):
        cdef sepol.type_datum_t *datum
        super().__next__()

        datum = <sepol.type_datum_t *> self.curr.datum
        while datum.flavor != sepol.TYPE_TYPE or type_is_alias(datum):
            super().__next__()
            datum = <sepol.type_datum_t *> self.curr.datum

        return Type.factory(self.policy, datum)

    def __len__(self):
        cdef sepol.type_datum_t *datum
        cdef sepol.hashtab_node_t *node
        cdef uint32_t bucket = 0
        cdef size_t count = 0

        while bucket < self.table[0].size:
            node = self.table[0].htable[bucket]
            while node != NULL:
                datum = <sepol.type_datum_t *>node.datum if node else NULL
                if datum != NULL and datum.flavor == sepol.TYPE_TYPE and not type_is_alias(datum):
                    count += 1

                node = node.next

            bucket += 1

        return count

    def reset(self):
        super().reset()

        # advance over any attributes or aliases
        while (<sepol.type_datum_t *> self.node.datum).flavor != sepol.TYPE_TYPE:
            self._next_node()


cdef class TypeAttributeHashtabIterator(HashtabIterator):

    """Iterate over type attributes in the policy."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.hashtab_t *table):
        """Factory function for creating Role iterators."""
        i = TypeAttributeHashtabIterator()
        i.policy = policy
        i.table = table
        i.reset()
        return i

    def __next__(self):
        super().__next__()
        while (<sepol.type_datum_t *> self.curr.datum).flavor != sepol.TYPE_ATTRIB:
            super().__next__()

        return TypeAttribute.factory(self.policy, <sepol.type_datum_t *> self.curr.datum)

    def __len__(self):
        cdef sepol.type_datum_t *datum
        cdef sepol.hashtab_node_t *node
        cdef uint32_t bucket = 0
        cdef size_t count = 0

        while bucket < self.table[0].size:
            node = self.table[0].htable[bucket]
            while node != NULL:
                datum = <sepol.type_datum_t *>node.datum if node else NULL
                if datum != NULL and datum.flavor == sepol.TYPE_ATTRIB:
                    count += 1

                node = node.next

            bucket += 1

        return count

    def reset(self):
        super().reset()

        # advance over any attributes or aliases
        while (<sepol.type_datum_t *> self.node.datum).flavor != sepol.TYPE_ATTRIB:
            self._next_node()


cdef class TypeAliasHashtabIterator(HashtabIterator):

    """Iterate over type aliases in the policy."""

    cdef uint32_t primary

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.hashtab_t *table, Type primary):
        """Factory function for creating type alias iterators."""
        i = TypeAliasHashtabIterator()
        i.policy = policy
        i.table = table
        i.primary = primary.handle.s.value
        i.reset()
        return i

    def __next__(self):
        super().__next__()
        datum = <sepol.type_datum_t *> self.curr.datum if self.curr else NULL

        while datum != NULL and (not type_is_alias(datum) or datum.s.value != self.primary):
            super().__next__()
            datum = <sepol.type_datum_t *> self.curr.datum if self.curr else NULL

        return intern(self.curr.key)

    def __len__(self):
        cdef sepol.type_datum_t *datum
        cdef sepol.hashtab_node_t *node
        cdef uint32_t bucket = 0
        cdef size_t count = 0

        while bucket < self.table[0].size:
            node = self.table[0].htable[bucket]
            while node != NULL:
                datum = <sepol.type_datum_t *>node.datum if node else NULL
                if datum != NULL and self.primary == datum.s.value and type_is_alias(datum):
                    count += 1

                node = node.next

            bucket += 1

        return count

    def reset(self):
        super().reset()

        cdef sepol.type_datum_t *datum = <sepol.type_datum_t *> self.node.datum if self.node else NULL

        # advance over any attributes or aliases
        while datum != NULL and (not type_is_alias(datum) and self.primary != datum.s.value):
            self._next_node()

            if self.node == NULL or self.bucket >= self.table[0].size:
                break

            datum = <sepol.type_datum_t *> self.node.datum if self.node else NULL


#
# Ebitmap Iterator Classes
#
cdef class TypeEbitmapIterator(EbitmapIterator):

    """Iterate over a type ebitmap."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.ebitmap_t *symbol):
        """Factory function for creating TypeEbitmapIterator."""
        i = TypeEbitmapIterator()
        i.policy = policy
        i.bmap = symbol
        i.reset()
        return i

    @staticmethod
    cdef factory_from_set(SELinuxPolicy policy, sepol.type_set_t *symbol):
        """Factory function for creating TypeEbitmapIterator from a type set."""
        if symbol.flags:
            warnings.warn("* or ~ in the type set; this is not implemented in SETools.")
        if symbol.negset.node != NULL:
            warnings.warn("Negations in the type set; this is not implemented in SETools.")

        return TypeEbitmapIterator.factory(policy, &symbol.types)

    def __next__(self):
        super().__next__()
        return Type.factory(self.policy, self.policy.handle.p.p.type_val_to_struct[self.bit])


cdef class TypeAttributeEbitmapIterator(EbitmapIterator):

    """Iterate over a type attribute ebitmap."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.ebitmap_t *bmap):
        """Factory function for creating TypeAttributeEbitmapIterator."""
        i = TypeAttributeEbitmapIterator()
        i.policy = policy
        i.bmap = bmap
        i.reset()
        return i

    @staticmethod
    cdef factory_from_set(SELinuxPolicy policy, sepol.type_set_t *symbol):
        """Factory function for creating TypeAttributeEbitmapIterator from a type set."""
        if symbol.flags:
            warnings.warn("* or ~ in the type set; this is not implemented in SETools.")
        if symbol.negset.node != NULL:
            warnings.warn("Negations in the type set; this is not implemented in SETools.")

        return TypeAttributeEbitmapIterator.factory(policy, &symbol.types)

    def __next__(self):
        super().__next__()
        return TypeAttribute.factory(self.policy,
                                     self.policy.handle.p.p.type_val_to_struct[self.bit])
