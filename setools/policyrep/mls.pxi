# Copyright 2014-2016, Tresys Technology, LLC
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
# pylint: disable=protected-access
import itertools

cdef dict _cat_cache = {}
cdef dict _sens_cache = {}
cdef dict _leveldecl_cache = {}


#
# Classes
#
cdef list expand_cat_range(SELinuxPolicy policy, Category low, Category high):
    """
    Helper function to expand a category range, e.g. c0.c1023
    into the full set of categories by using the low and high
    categories of the set.
    """

    cdef list expanded
    expanded = [low, high]
    for value in range(low._value, high._value):
        expanded.append(Category.factory(policy, policy.category_value_to_datum(value)))

    return expanded


cdef class Category(PolicySymbol):

    """An MLS category."""

    cdef sepol.cat_datum_t *handle

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.cat_datum_t *symbol):
        """Factory function for creating Category objects."""
        if not policy.mls:
            raise MLSDisabled

        try:
            return _cat_cache[<uintptr_t>symbol]
        except KeyError:
            c = Category()
            c.policy = policy
            c.handle = symbol
            _cat_cache[<uintptr_t>symbol] = c
            return c

    def __str__(self):
        return self.policy.category_value_to_name(self.handle.s.value - 1)

    def __hash__(self):
        return hash(str(self))

    def __lt__(self, other):
        # Comparison based on their index instead of their names.
        return self._value < other._value

    def _eq(self, Category other):
        """Low-level equality check (C pointers)."""
        return self.handle == other.handle

    @property
    def _value(self):
        """
        The value of the category.

        This is a low-level policy detail exposed for internal use only.
        """
        return self.handle.s.value

    def aliases(self):
        """Generator that yields all aliases for this category."""
        return self.policy.category_aliases(self)

    def statement(self):
        aliases = list(self.aliases())
        stmt = "category {0}".format(self)
        if aliases:
            if len(aliases) > 1:
                stmt += " alias {{ {0} }}".format(' '.join(aliases))
            else:
                stmt += " alias {0}".format(aliases[0])
        stmt += ";"
        return stmt


cdef class Sensitivity(PolicySymbol):

    """An MLS sensitivity"""

    cdef sepol.level_datum_t *handle

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.level_datum_t *symbol):
        """Factory function for creating Sensitivity objects."""
        if not policy.mls:
            raise MLSDisabled

        try:
            return _sens_cache[<uintptr_t>symbol]
        except KeyError:
            s = Sensitivity()
            s.policy = policy
            s.handle = symbol
            _sens_cache[<uintptr_t>symbol] = s
            return s

    def __str__(self):
        return self.policy.level_value_to_name(self.handle.level.sens - 1)

    def __hash__(self):
        return hash(str(self))

    def __ge__(self, other):
        return self._value >= other._value

    def __gt__(self, other):
        return self._value > other._value

    def __le__(self, other):
        return self._value <= other._value

    def __lt__(self, other):
        return self._value < other._value

    def _eq(self, Sensitivity other):
        """Low-level equality check (C pointers)."""
        return self.handle == other.handle

    @property
    def _value(self):
        """
        The value of the component.

        This is a low-level policy detail exposed for internal use only.
        """
        return self.handle.level.sens

    def aliases(self):
        """Generator that yields all aliases for this sensitivity."""
        return self.policy.sensitivity_aliases(self)

    def level_decl(self):
        """Get the level declaration corresponding to this sensitivity."""
        return LevelDecl.factory(self.policy, self.handle)

    def statement(self):
        aliases = list(self.aliases())
        stmt = "sensitivity {0}".format(self)
        if aliases:
            if len(aliases) > 1:
                stmt += " alias {{ {0} }}".format(' '.join(aliases))
            else:
                stmt += " alias {0}".format(aliases[0])
        stmt += ";"
        return stmt


cdef class BaseMLSLevel(PolicySymbol):

    """Base class for MLS levels."""

    def __str__(self):
        lvl = str(self.sensitivity)

        # sort by policy declaration order
        cats = sorted(self.categories(), key=lambda k: k._value)

        if cats:
            # generate short category notation
            shortlist = []
            for _, i in itertools.groupby(cats, key=lambda k,
                                          c=itertools.count(): k._value - next(c)):
                group = list(i)
                if len(group) > 1:
                    shortlist.append("{0}.{1}".format(group[0], group[-1]))
                else:
                    shortlist.append(str(group[0]))

            lvl += ":" + ','.join(shortlist)

        return lvl

    def categories(self):
        """
        Generator that yields all individual categories for this level.
        All categories are yielded, not a compact notation such as
        c0.c255
        """
        raise NotImplementedError

    @property
    def sensitivity(self):
        raise NotImplementedError


cdef class LevelDecl(BaseMLSLevel):

    """
    The declaration statement for MLS levels, e.g:

    level s7:c0.c1023;
    """

    cdef sepol.level_datum_t *handle

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.level_datum_t *symbol):
        """Factory function for creating LevelDecl objects."""
        if not policy.mls:
            raise MLSDisabled

        try:
            return _leveldecl_cache[<uintptr_t>symbol]
        except KeyError:
            l = LevelDecl()
            l.policy = policy
            l.handle = symbol
            _leveldecl_cache[<uintptr_t>symbol] = l
            return l

    def __hash__(self):
        return hash(self.sensitivity)

    # below comparisons are only based on sensitivity
    # dominance since, in this context, the allowable
    # category set is being defined for the level.
    # object type is asserted here because this cannot
    # be compared to a Level instance.

    def __eq__(self, other):
        assert not isinstance(other, Level), "Levels cannot be compared to level declarations"

        try:
            return self.sensitivity == other.sensitivity
        except AttributeError:
            return str(self) == str(other)

    def __ge__(self, other):
        assert not isinstance(other, Level), "Levels cannot be compared to level declarations"
        return self.sensitivity >= other.sensitivity

    def __gt__(self, other):
        assert not isinstance(other, Level), "Levels cannot be compared to level declarations"
        return self.sensitivity > other.sensitivity

    def __le__(self, other):
        assert not isinstance(other, Level), "Levels cannot be compared to level declarations"
        return self.sensitivity <= other.sensitivity

    def __lt__(self, other):
        assert not isinstance(other, Level), "Levels cannot be compared to level declarations"
        return self.sensitivity < other.sensitivity

    def _eq(self, LevelDecl other):
        """Low-level equality check (C pointers)."""
        return self.handle == other.handle

    def categories(self):
        """
        Generator that yields all individual categories for this level.
        All categories are yielded, not a compact notation such as
        c0.c255
        """
        return CategoryEbitmapIterator.factory(self.policy, &self.handle.level.cat)

    @property
    def sensitivity(self):
        """The sensitivity of the level."""
        # since the datum for levels is also used for
        # Sensitivity objects, use self's datum
        return Sensitivity.factory(self.policy, self.handle)

    def statement(self):
        return "level {0};".format(self)


cdef class Level(BaseMLSLevel):

    """
    An MLS level used in contexts.

    The _sensitivity and _categories attributes are only populated
    if the level is user-generated.
    """

    cdef:
        sepol.mls_level_t *handle
        list _categories
        Sensitivity _sensitivity

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.mls_level_t *symbol):
        """Factory function for creating Level objects."""
        if not policy.mls:
            raise MLSDisabled

        l = Level()
        l.policy = policy
        l.handle = symbol
        return l

    @staticmethod
    cdef factory_from_string(SELinuxPolicy policy, str name):
        """Factory function variant for constructing Level objects by a string."""

        if not policy.mls:
            raise MLSDisabled

        sens_split = name.split(":")
        sens = sens_split[0]

        try:
            s = policy.lookup_sensitivity(sens)
        except InvalidSensitivity as ex:
            raise InvalidLevel("{0} is not a valid level ({1} is not a valid sensitivity)". \
                               format(name, sens)) from ex

        c = []

        try:
            cats = sens_split[1]
        except IndexError:
            pass
        else:
            for group in cats.split(","):
                catrange = group.split(".")
                if len(catrange) == 2:
                    try:
                        c.extend(expand_cat_range(policy,
                                                  policy.lookup_category(catrange[0]),
                                                  policy.lookup_category(catrange[1])))
                    except InvalidCategory as ex:
                        raise InvalidLevel(
                            "{0} is not a valid level ({1} is not a valid category range)".
                            format(name, group)) from ex

                elif len(catrange) == 1:
                    try:
                        c.append(policy.lookup_category(catrange[0]))
                    except InvalidCategory as ex:
                        raise InvalidLevel("{0} is not a valid level ({1} is not a valid category)".
                                           format(name, group)) from ex

                else:
                    raise InvalidLevel("{0} is not a valid level (level parsing error)".format(name))

        # build object
        l = Level()
        l.policy = policy
        l.handle = NULL
        l._sensitivity = s
        l._categories = c

        # verify level is valid
        if not l <= s.level_decl():
            raise InvalidLevel(
                "{0} is not a valid level (one or more categories are not associated with the "
                "sensitivity)".format(name))

        return l

    def __hash__(self):
        return hash(str(self))

    def __eq__(self, other):
        try:
            othercats = set(other.categories())
        except AttributeError:
            return str(self) == str(other)
        else:
            selfcats = set(self.categories())
            return self.sensitivity == other.sensitivity and selfcats == othercats

    def __ge__(self, other):
        # Dom operator
        selfcats = set(self.categories())
        othercats = set(other.categories())
        return self.sensitivity >= other.sensitivity and selfcats >= othercats

    def __gt__(self, other):
        selfcats = set(self.categories())
        othercats = set(other.categories())
        return ((self.sensitivity > other.sensitivity and selfcats >= othercats) or
                (self.sensitivity >= other.sensitivity and selfcats > othercats))

    def __le__(self, other):
        # Domby operator
        selfcats = set(self.categories())
        othercats = set(other.categories())
        return self.sensitivity <= other.sensitivity and selfcats <= othercats

    def __lt__(self, other):
        selfcats = set(self.categories())
        othercats = set(other.categories())
        return ((self.sensitivity < other.sensitivity and selfcats <= othercats) or
                (self.sensitivity <= other.sensitivity and selfcats < othercats))

    def __xor__(self, other):
        # Incomp operator
        return not (self >= other or self <= other)

    def _eq(self, Level other):
        """Low-level equality check (C pointers)."""
        return self.handle == other.handle

    def categories(self):
        """
        Generator that yields all individual categories for this level.
        All categories are yielded, not a compact notation such as
        c0.c255
        """
        if self.handle == NULL:
            return iter(self._categories)
        else:
            return CategoryEbitmapIterator.factory(self.policy, &self.handle.cat)

    @property
    def sensitivity(self):
        """The sensitivity of the level."""
        if self.handle == NULL:
            return self._sensitivity
        else:
            return Sensitivity.factory(self.policy,
                                       self.policy.level_value_to_datum(self.handle.sens - 1))

    def statement(self):
        raise NoStatement


cdef class Range(PolicySymbol):

    """An MLS range"""

    cdef:
        sepol.mls_range_t *handle
        Level _low
        Level _high

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.mls_range_t *symbol):
        """Factory function for creating Range objects."""
        if not policy.mls:
            raise MLSDisabled

        r = Range()
        r.policy = policy
        r.handle = symbol
        return r

    @staticmethod
    cdef factory_from_string(SELinuxPolicy policy, str name):
        """Factory function variant for constructing Range objects by name."""
        if not policy.mls:
            raise MLSDisabled

        # build range:
        levels = name.split("-")

        # strip() levels to handle ranges with spaces in them,
        # e.g. s0:c1 - s0:c0.c255
        try:
            low = Level.factory_from_string(policy, levels[0].strip())
        except InvalidLevel as ex:
            raise InvalidRange("{0} is not a valid range ({1}).".format(name, ex)) from ex

        try:
            high = Level.factory_from_string(policy, levels[1].strip())
        except InvalidLevel as ex:
            raise InvalidRange("{0} is not a valid range ({1}).".format(name, ex)) from ex
        except IndexError:
            high = low

        # verify high level dominates low range
        if not high >= low:
            raise InvalidRange("{0} is not a valid range ({1} is not dominated by {2})".
                               format(name, low, high))

        r = Range()
        r.policy = policy
        r.handle = NULL
        r._low = low
        r._high = high
        return r

    def __str__(self):
        high = self.high
        low = self.low
        if high == low:
            return str(low)

        return "{0} - {1}".format(low, high)

    def __hash__(self):
        return hash(str(self))

    def __eq__(self, other):
        try:
            return self.low == other.low and self.high == other.high
        except AttributeError:
            # remove all spaces in the string representations
            # to handle cases where the other object does not
            # have spaces around the '-'
            other_str = str(other).replace(" ", "")
            self_str = str(self).replace(" ", "")
            return self_str == other_str

    def __contains__(self, other):
        return self.low <= other <= self.high

    def _eq(self, Range other):
        """Low-level equality check (C pointers)."""
        return self.handle == other.handle

    @property
    def high(self):
        """The high end/clearance level of this range."""
        if self.handle == NULL:
            return self._high
        else:
            return Level.factory(self.policy, &self.handle.level[1])

    @property
    def low(self):
        """The low end/current level of this range."""
        if self.handle == NULL:
            return self._low
        else:
            return Level.factory(self.policy, &self.handle.level[0])

    def statement(self):
        raise NoStatement


#
# Hash Table Iterators
#
cdef class CategoryHashtabIterator(HashtabIterator):

    """Iterate over categories in the policy."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.hashtab_t *table):
        """Factory function for creating category iterators."""
        i = CategoryHashtabIterator()
        i.policy = policy
        i.table = table
        i.reset()
        return i

    def __next__(self):
        super().__next__()
        datum = <sepol.cat_datum_t *> self.curr.datum if self.curr else NULL

        while datum != NULL and datum.isalias:
            super().__next__()
            datum = <sepol.cat_datum_t *> self.curr.datum if self.curr else NULL

        return Category.factory(self.policy, datum)

    def __len__(self):
        cdef sepol.cat_datum_t *datum
        cdef sepol.hashtab_node_t *node
        cdef uint32_t bucket = 0
        cdef size_t count = 0

        while bucket < self.table[0].size:
            node = self.table[0].htable[bucket]
            while node != NULL:
                datum = <sepol.cat_datum_t *>node.datum if node else NULL
                if datum != NULL and not datum.isalias:
                    count += 1

                node = node.next

            bucket += 1

        return count

    def reset(self):
        super().reset()

        cdef sepol.cat_datum_t *datum = <sepol.cat_datum_t *> self.node.datum if self.node else NULL

        # advance over any attributes or aliases
        while datum != NULL and datum.isalias:
            self._next_node()

            if self.node == NULL or self.bucket >= self.table[0].size:
                break

            datum = <sepol.cat_datum_t *> self.node.datum if self.node else NULL


cdef class CategoryAliasHashtabIterator(HashtabIterator):

    """Iterate over category aliases in the policy."""

    cdef uint32_t primary

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.hashtab_t *table, Category primary):
        """Factory function for creating category alias iterators."""
        i = CategoryAliasHashtabIterator()
        i.policy = policy
        i.table = table
        i.primary = primary._value
        i.reset()
        return i

    def __next__(self):
        super().__next__()
        datum = <sepol.cat_datum_t *> self.curr.datum if self.curr else NULL

        while datum != NULL and (not datum.isalias or datum.s.value != self.primary):
            super().__next__()
            datum = <sepol.cat_datum_t *> self.curr.datum if self.curr else NULL

        return intern(self.curr.key)

    def __len__(self):
        cdef sepol.cat_datum_t *datum
        cdef sepol.hashtab_node_t *node
        cdef uint32_t bucket = 0
        cdef size_t count = 0

        while bucket < self.table[0].size:
            node = self.table[0].htable[bucket]
            while node != NULL:
                datum = <sepol.cat_datum_t *>node.datum if node else NULL
                if datum != NULL and self.primary == datum.s.value and datum.isalias:
                    count += 1

                node = node.next

            bucket += 1

        return count

    def reset(self):
        super().reset()

        cdef sepol.cat_datum_t *datum = <sepol.cat_datum_t *> self.node.datum if self.node else NULL

        # advance over any attributes or aliases
        while datum != NULL and (not datum.isalias and self.primary != datum.s.value):
            self._next_node()

            if self.node == NULL or self.bucket >= self.table[0].size:
                break

            datum = <sepol.cat_datum_t *> self.node.datum if self.node else NULL


cdef class SensitivityHashtabIterator(HashtabIterator):

    """Iterate over sensitivity in the policy."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.hashtab_t *table):
        """Factory function for creating category iterators."""
        i = SensitivityHashtabIterator()
        i.policy = policy
        i.table = table
        i.reset()
        return i

    def __next__(self):
        super().__next__()
        datum = <sepol.level_datum_t *> self.curr.datum if self.curr else NULL

        while datum != NULL and datum.isalias:
            super().__next__()
            datum = <sepol.level_datum_t *> self.curr.datum if self.curr else NULL

        return Sensitivity.factory(self.policy, datum)

    def __len__(self):
        cdef sepol.level_datum_t *datum
        cdef sepol.hashtab_node_t *node
        cdef uint32_t bucket = 0
        cdef size_t count = 0

        while bucket < self.table[0].size:
            node = self.table[0].htable[bucket]
            while node != NULL:
                datum = <sepol.level_datum_t *>node.datum if node else NULL
                if datum != NULL and not datum.isalias:
                    count += 1

                node = node.next

            bucket += 1

        return count

    def reset(self):
        super().reset()

        cdef sepol.level_datum_t *datum = <sepol.level_datum_t *> self.node.datum if self.node else NULL

        # advance over any attributes or aliases
        while datum != NULL and datum.isalias:
            self._next_node()

            if self.node == NULL or self.bucket >= self.table[0].size:
                break

            datum = <sepol.level_datum_t *> self.node.datum if self.node else NULL


cdef class SensitivityAliasHashtabIterator(HashtabIterator):

    """Iterate over sensitivity aliases in the policy."""

    cdef uint32_t primary

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.hashtab_t *table, Sensitivity primary):
        """Factory function for creating Sensitivity alias iterators."""
        i = SensitivityAliasHashtabIterator()
        i.policy = policy
        i.table = table
        i.primary = primary._value
        i.reset()
        return i

    def __next__(self):
        super().__next__()
        datum = <sepol.level_datum_t *> self.curr.datum if self.curr else NULL

        while datum != NULL and (not datum.isalias or datum.level.sens != self.primary):
            super().__next__()
            datum = <sepol.level_datum_t *> self.curr.datum if self.curr else NULL

        return intern(self.curr.key)

    def __len__(self):
        cdef sepol.level_datum_t *datum
        cdef sepol.hashtab_node_t *node
        cdef uint32_t bucket = 0
        cdef size_t count = 0

        while bucket < self.table[0].size:
            node = self.table[0].htable[bucket]
            while node != NULL:
                datum = <sepol.level_datum_t *>node.datum if node else NULL
                if datum != NULL and self.primary == datum.level.sens and datum.isalias:
                    count += 1

                node = node.next

            bucket += 1

        return count

    def reset(self):
        super().reset()

        cdef sepol.level_datum_t *datum = <sepol.level_datum_t *> self.node.datum if self.node else NULL

        # advance over any attributes or aliases
        while datum != NULL and (not datum.isalias and self.primary != datum.level.sens):
            self._next_node()

            if self.node == NULL or self.bucket >= self.table[0].size:
                break

            datum = <sepol.level_datum_t *> self.node.datum if self.node else NULL


cdef class LevelDeclHashtabIterator(HashtabIterator):

    """Iterate over level declarations in the policy."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.hashtab_t *table):
        """Factory function for creating level declarations iterators."""
        i = LevelDeclHashtabIterator()
        i.policy = policy
        i.table = table
        i.reset()
        return i

    def __next__(self):
        super().__next__()
        datum = <sepol.level_datum_t *> self.curr.datum if self.curr else NULL

        while datum != NULL and datum.isalias:
            super().__next__()
            datum = <sepol.level_datum_t *> self.curr.datum if self.curr else NULL

        return LevelDecl.factory(self.policy, datum)

    def __len__(self):
        cdef sepol.level_datum_t *datum
        cdef sepol.hashtab_node_t *node
        cdef uint32_t bucket = 0
        cdef size_t count = 0

        while bucket < self.table[0].size:
            node = self.table[0].htable[bucket]
            while node != NULL:
                datum = <sepol.level_datum_t *>node.datum if node else NULL
                if datum != NULL and not datum.isalias:
                    count += 1

                node = node.next

            bucket += 1

        return count

    def reset(self):
        super().reset()

        cdef sepol.level_datum_t *datum = <sepol.level_datum_t *> self.node.datum if self.node else NULL

        # advance over any attributes or aliases
        while datum != NULL and datum.isalias:
            self._next_node()

            if self.node == NULL or self.bucket >= self.table[0].size:
                break

            datum = <sepol.level_datum_t *> self.node.datum if self.node else NULL


#
# Ebitmap Iterators
#
cdef class CategoryEbitmapIterator(EbitmapIterator):

    """Iterate over a category ebitmap."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.ebitmap_t *symbol):
        """Factory function for creating CategoryEbitmapIterator."""
        i = CategoryEbitmapIterator()
        i.policy = policy
        i.bmap = symbol
        i.reset()
        return i

    def __next__(self):
        super().__next__()
        return Category.factory(self.policy, self.policy.category_value_to_datum(self.bit))
