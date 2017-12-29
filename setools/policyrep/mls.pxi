# Copyright 2014-2016, Tresys Technology, LLC
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
# pylint: disable=protected-access
import itertools

# qpol does not expose an equivalent of a sensitivity declaration.
# qpol_level_t is equivalent to the level declaration:
#   level s0:c0.c1023;

# qpol_mls_level_t represents a level as used in contexts,
# such as range_transitions or labeling statements such as
# portcon and nodecon.

# Here qpol_level_t is also used for MLSSensitivity
# since it has the sensitivity name, dominance, and there
# is a 1:1 correspondence between the sensitivity declarations
# and level declarations.

# Hashing has to be handled below because the qpol references,
# normally used for a hash key, are not the same for multiple
# instances of the same object (except for level decl).


#
# Category factory functions
#
cdef inline Category category_factory_lookup(SELinuxPolicy policy, str name):
    """Factory function variant for constructing Category objects by name."""
    if not policy.mls:
        raise MLSDisabled

    cdef const qpol_cat_t *symbol
    if qpol_policy_get_cat_by_name(policy.handle, name, &symbol):
        raise InvalidCategory("{0} is not a valid category".format(name))

    return category_factory(policy, symbol)


cdef inline Category category_factory_iter(SELinuxPolicy policy, QpolIteratorItem symbol):
    """Factory function variant for iterating over Category objects."""
    return category_factory(policy, <const qpol_cat_t *> symbol.obj)


cdef inline Category category_factory(SELinuxPolicy policy, const qpol_cat_t *symbol):
    """Factory function for creating Category objects."""
    cdef unsigned char isalias
    cdef const char *name

    if not policy.mls:
        raise MLSDisabled

    if qpol_cat_get_isalias(policy.handle, symbol, &isalias):
        ex = LowLevelPolicyError("Error determining category alias status: {}".format(
                                 strerror(errno)))
        ex.errno = errno
        raise ex

    if isalias:
        if qpol_cat_get_name(policy.handle, symbol, &name):
            raise ValueError("The category is an alias")

        raise ValueError("{0} is an alias".format(name))

    r = Category()
    r.policy = policy
    r.handle = symbol
    return r


#
# Sensitivity factory functions
#
cdef inline Sensitivity sensitivity_factory_lookup(SELinuxPolicy policy, str name):
    """Factory function variant for constructing Sensitivity objects by name."""
    cdef const qpol_level_t *symbol

    if not policy.mls:
        raise MLSDisabled

    if qpol_policy_get_level_by_name(policy.handle, name, &symbol):
        raise InvalidSensitivity("{0} is not a valid sensitivity".format(name))

    return sensitivity_factory(policy, symbol)


cdef inline Sensitivity sensitivity_factory_iter(SELinuxPolicy policy, QpolIteratorItem symbol):
    """Factory function variant for iterating over Sensitivity objects."""
    return sensitivity_factory(policy, <const qpol_level_t *> symbol.obj)


cdef inline Sensitivity sensitivity_factory(SELinuxPolicy policy, const qpol_level_t *symbol):
    """Factory function for creating Sensitivity objects."""
    cdef unsigned char isalias
    cdef const char *name

    if not policy.mls:
        raise MLSDisabled

    if qpol_level_get_isalias(policy.handle, symbol, &isalias):
        ex = LowLevelPolicyError("Error determining sensitivity alias status: {}".format(
                                 strerror(errno)))
        ex.errno = errno
        raise ex

    if isalias:
        if qpol_level_get_name(policy.handle, symbol, &name):
            raise ValueError("The sensitivity is an alias")

        raise ValueError("{0} is an alias".format(name))

    r = Sensitivity()
    r.policy = policy
    r.handle = symbol
    return r


#
# Level declaration factory functions
#
cdef inline LevelDecl level_decl_factory_iter(SELinuxPolicy policy, QpolIteratorItem symbol):
    """Factory function variant for iterating over LevelDecl objects."""
    return level_decl_factory(policy, <const qpol_level_t *> symbol.obj)


cdef inline LevelDecl level_decl_factory(SELinuxPolicy policy, const qpol_level_t *symbol):
    """Factory function for creating LevelDecl objects."""
    cdef unsigned char isalias
    cdef const char *name

    if not policy.mls:
        raise MLSDisabled

    if qpol_level_get_isalias(policy.handle, symbol, &isalias):
        ex = LowLevelPolicyError("Error determining level alias status: {}".format(
                                 strerror(errno)))
        ex.errno = errno
        raise ex

    if isalias:
        if qpol_level_get_name(policy.handle, symbol, &name):
            raise ValueError("The level decl is an alias")

        raise ValueError("{0} is an alias".format(name))

    r = LevelDecl()
    r.policy = policy
    r.handle = symbol
    return r


#
# Level factory functions
#
cdef inline Level level_factory_lookup(SELinuxPolicy policy, str name):
    """Factory function variant for constructing Level objects by name."""
    cdef qpol_semantic_level_t *l
    cdef qpol_mls_level_t *level

    if not policy.mls:
        raise MLSDisabled

    sens_split = name.split(":")
    sens = sens_split[0]

    if qpol_policy_get_semantic_level_by_name(policy.handle, sens, &l):
        raise InvalidLevel("{0} is not a valid level ({1} is not a valid sensitivity)". \
                           format(name, sens))

    try:
        cats = sens_split[1]
    except IndexError:
        pass
    else:
        for group in cats.split(","):
            catrange = group.split(".")

            if len(catrange) == 2:
                if qpol_semantic_level_add_cats_by_name(policy.handle, l, catrange[0], catrange[1]):

                    raise InvalidLevel(
                        "{0} is not a valid level ({1} is not a valid category range)".
                        format(name, group))

            elif len(catrange) == 1:
                if qpol_semantic_level_add_cats_by_name(policy.handle, l, catrange[0], catrange[0]):

                    raise InvalidLevel("{0} is not a valid level ({1} is not a valid category)".
                                       format(name, group))

            else:
                raise InvalidLevel("{0} is not a valid level (level parsing error)".format(name))

    # convert to level symbol
    if qpol_mls_level_from_semantic_level(policy.handle, l, &level):
        raise InvalidLevel(
            "{0} is not a valid level (one or more categories are not associated with the "
            "sensitivity)".format(name))

    qpol_semantic_level_destroy(l)

    # TODO: since this is user-generated, the level will need a destructor
    return level_factory(policy, level)


cdef inline Level level_factory(SELinuxPolicy policy, const qpol_mls_level_t *symbol):
    """Factory function for creating Level objects."""
    if not policy.mls:
        raise MLSDisabled

    r = Level()
    r.policy = policy
    r.handle = symbol
    return r


#
# Range factory functions
#
cdef inline Range range_factory_lookup(SELinuxPolicy policy, str name):
    """Factory function variant for constructing Range objects by name."""
    cdef qpol_mls_range_t *range

    if not policy.mls:
        raise MLSDisabled

    # build range:
    levels = name.split("-")

    # strip() levels to handle ranges with spaces in them,
    # e.g. s0:c1 - s0:c0.c255
    try:
        low = level_factory_lookup(policy, levels[0].strip())
    except InvalidLevel as ex:
        raise InvalidRange("{0} is not a valid range ({1}).".format(name, ex)) from ex

    try:
        high = level_factory_lookup(policy, levels[1].strip())
    except InvalidLevel as ex:
        raise InvalidRange("{0} is not a valid range ({1}).".format(name, ex)) from ex
    except IndexError:
        high = low

    # convert to range object
    if qpol_policy_get_mls_range_from_mls_levels(policy.handle, low.handle, high.handle, &range):
        raise InvalidRange("{0} is not a valid range ({1} is not dominated by {2})".
                           format(name, low, high))

    # TODO: since this is user-generated, the range will need a destructor
    return range_factory(policy, range)


cdef inline Range range_factory(SELinuxPolicy policy, const qpol_mls_range_t *symbol):
    """Factory function for creating Range objects."""
    if not policy.mls:
        raise MLSDisabled

    r = Range()
    r.policy = policy
    r.handle = symbol
    return r


#
# Classes
#
cdef class Category(PolicySymbol):

    """An MLS category."""

    cdef const qpol_cat_t *handle

    def __str__(self):
        cdef const char *name

        if qpol_cat_get_name(self.policy.handle, self.handle, &name):
            ex = LowLevelPolicyError("Error reading category name: {}".format(strerror(errno)))
            ex.errno = errno
            raise ex

        return name

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
        The value of the component.

        This is a low-level policy detail exposed for internal use only.
        """
        cdef uint32_t v
        if qpol_cat_get_value(self.policy.handle, self.handle, &v):
            ex = LowLevelPolicyError("Error reading category value: {}".format(strerror(errno)))
            ex.errno = errno
            raise ex

        return v

    def aliases(self):
        """Generator that yields all aliases for this category."""
        cdef qpol_iterator_t *iter
        if qpol_cat_get_alias_iter(self.policy.handle, self.handle, &iter):
            raise MemoryError

        return qpol_iterator_factory(self.policy, iter, string_factory_iter)

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

    cdef const qpol_level_t *handle

    def __str__(self):
        cdef const char *name

        if qpol_level_get_name(self.policy.handle, self.handle, &name):
            ex = LowLevelPolicyError("Error reading sensitivity name: {}".format(strerror(errno)))
            ex.errno = errno
            raise ex

        return name

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
        cdef uint32_t v
        if qpol_level_get_value(self.policy.handle, self.handle, &v):
            ex = LowLevelPolicyError("Error reading sensitivity value: {}".format(strerror(errno)))
            ex.errno = errno
            raise ex

        return v

    def aliases(self):
        """Generator that yields all aliases for this sensitivity."""
        cdef qpol_iterator_t *iter
        if qpol_level_get_alias_iter(self.policy.handle, self.handle, &iter):
            raise MemoryError

        return qpol_iterator_factory(self.policy, iter, string_factory_iter)

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

    cdef const qpol_level_t *handle

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
        cdef qpol_iterator_t *iter
        if qpol_level_get_cat_iter(self.policy.handle, self.handle, &iter):
            raise MemoryError

        return qpol_iterator_factory(self.policy, iter, category_factory_iter)

    @property
    def sensitivity(self):
        """The sensitivity of the level."""
        # since the qpol symbol for levels is also used for
        # MLSSensitivity objects, use self's qpol symbol
        return sensitivity_factory(self.policy, self.handle)

    def statement(self):
        return "level {0};".format(self)


cdef class Level(BaseMLSLevel):

    """An MLS level used in contexts."""

    cdef const qpol_mls_level_t *handle

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
        cdef qpol_iterator_t *iter
        if qpol_mls_level_get_cat_iter(self.policy.handle, self.handle, &iter):
            raise MemoryError

        return qpol_iterator_factory(self.policy, iter, category_factory_iter)


    @property
    def sensitivity(self):
        """The sensitivity of the level."""
        cdef const char *name
        if qpol_mls_level_get_sens_name(self.policy.handle, self.handle, &name):
            ex = LowLevelPolicyError("Error reading level sensitivity name: {}".format(
                                     strerror(errno)))
            ex.errno = errno
            raise ex

        return sensitivity_factory_lookup(self.policy, name)

    def statement(self):
        raise NoStatement


cdef class Range(PolicySymbol):

    """An MLS range"""

    cdef const qpol_mls_range_t *handle

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
        cdef const qpol_mls_level_t *l
        if qpol_mls_range_get_high_level(self.policy.handle, self.handle, &l):
            ex = LowLevelPolicyError("Error reading range high level: {}".format(strerror(errno)))
            ex.errno = errno
            raise ex

        return level_factory(self.policy, l)

    @property
    def low(self):
        """The low end/current level of this range."""
        cdef const qpol_mls_level_t *l
        if qpol_mls_range_get_low_level(self.policy.handle, self.handle, &l):
            ex = LowLevelPolicyError("Error reading range low level: {}".format(strerror(errno)))
            ex.errno = errno
            raise ex

        return level_factory(self.policy, l)

    def statement(self):
        raise NoStatement
