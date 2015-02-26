# Copyright 2014-2015, Tresys Technology, LLC
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
import itertools

from . import qpol
from . import symbol

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


class InvalidSensitivity(symbol.InvalidSymbol):

    """
    Exception for an invalid sensitivity.
    """
    pass


class InvalidLevel(symbol.InvalidSymbol):

    """
    Exception for an invalid level.
    """
    pass


class InvalidRange(symbol.InvalidSymbol):

    """
    Exception for an invalid range.
    """
    pass


class MLSDisabled(Exception):

    """
    Exception when MLS is disabled.
    """
    pass


def category_factory(policy, symbol):
    """Factory function for creating MLS category objects."""

    if not isinstance(symbol, qpol.qpol_cat_t):
        raise NotImplementedError

    return MLSCategory(policy, symbol)


def sensitivity_factory(policy, symbol):
    """Factory function for creating MLS sensitivity objects."""
    if isinstance(symbol, qpol.qpol_level_t):
        return MLSSensitivity(policy, symbol)

    try:
        return MLSSensitivity(policy, qpol.qpol_level_t(policy, symbol))
    except ValueError:
        raise InvalidSensitivity("{0} is not a valid sensitivity".format(symbol))


def level_factory(policy, symbol):
    """
    Factory function for creating MLS level objects (e.g. levels used
    in contexts of labeling statements)
    """
    if isinstance(symbol, qpol.qpol_mls_level_t):
        return MLSLevel(policy, symbol)

    sens_split = symbol.split(":")

    sens = sens_split[0]
    try:
        semantic_level = qpol.qpol_semantic_level_t(policy, sens)
    except ValueError:
        raise InvalidLevel("{0} is invalid ({1} is not a valid sensitivity)".format(symbol, sens))

    try:
        cats = sens_split[1]
    except IndexError:
        pass
    else:
        for group in cats.split(","):
            catrange = group.split(".")

            if len(catrange) == 2:
                try:
                    semantic_level.add_cats(policy, catrange[0], catrange[1])
                except ValueError:
                    raise InvalidLevel("{0} is invalid ({1} is not a valid category range)".
                                       format(symbol, group))
            elif len(catrange) == 1:
                try:
                    semantic_level.add_cats(policy, catrange[0], catrange[0])
                except ValueError:
                    raise InvalidLevel("{0} is invalid  ({1} is not a valid category)".
                                       format(symbol, group))
            else:
                raise InvalidLevel("{0} is invalid (level parsing error)".format(symbol))

    # convert to level object
    try:
        policy_level = qpol.qpol_mls_level_t(policy, semantic_level)
    except ValueError:
        raise InvalidLevel(
            "{0} is invalid (one or more categories are not associated with the sensitivity)".
            format(symbol))

    return MLSLevel(policy, policy_level)


def level_decl_factory(policy, symbol):
    """
    Factory function for creating MLS level declaration objects.
    (level statements) Lookups are only by sensitivity name.
    """

    if isinstance(symbol, qpol.qpol_level_t):
        return MLSLevelDecl(policy, symbol)

    try:
        return MLSLevelDecl(policy, qpol.qpol_level_t(policy, symbol))
    except ValueError:
        raise InvalidLevel("{0} is not a valid sensitivity".format(symbol))


def range_factory(policy, symbol):
    """Factory function for creating MLS range objects."""
    if isinstance(symbol, qpol.qpol_mls_range_t):
        return MLSRange(policy, symbol)

    # build range:
    levels = symbol.split("-")

    # strip() levels to handle ranges with spaces in them,
    # e.g. s0:c1 - s0:c0.c255
    try:
        low = level_factory(policy, levels[0].strip())
    except InvalidLevel as e:
        raise InvalidRange("{0} is not a valid range ({1}).".format(symbol, e))

    try:
        high = level_factory(policy, levels[1].strip())
    except InvalidLevel as e:
        raise InvalidRange("{0} is not a valid range ({1}).".format(symbol, e))
    except IndexError:
        high = low

    # convert to range object
    try:
        policy_range = qpol.qpol_mls_range_t(policy, low.qpol_symbol, high.qpol_symbol)
    except ValueError:
        raise InvalidRange("{0} is not a valid range ({1} is not dominated by {2})".
                           format(symbol, low, high))

    return MLSRange(policy, policy_range)


class MLSCategory(symbol.PolicySymbol):

    """An MLS category."""

    def __hash__(self):
        return hash(self._value)

    @property
    def _value(self):
        """
        The value of the category.

        This is a low-level policy detail exposed so that categories can
        be sorted based on their policy declaration order instead of
        by their name.  This has no other use.

        Example usage: sorted(self.categories(), key=lambda k: k._value)
        """
        return self.qpol_symbol.value(self.policy)

    def aliases(self):
        """Generator that yields all aliases for this category."""

        for alias in self.qpol_symbol.alias_iter(self.policy):
            yield alias

    def statement(self):
        return "category {0};".format(self)


class MLSSensitivity(symbol.PolicySymbol):

    """An MLS sensitivity"""

    def __hash__(self):
        return hash(self._value)

    def __eq__(self, other):
        try:
            return (self._value == other._value)
        except AttributeError:
            return (str(self) == str(other))

    def __ge__(self, other):
        return (self._value >= other._value)

    def __gt__(self, other):
        return (self._value > other._value)

    def __le__(self, other):
        return (self._value <= other._value)

    def __lt__(self, other):
        return (self._value < other._value)

    @property
    def _value(self):
        """
        The value of the sensitivity.

        This is a low-level policy detail exposed so that sensitivities can
        be compared based on their dominance.  This has no other use.
        """
        return self.qpol_symbol.value(self.policy)

    def statement(self):
        return "sensitivity {0};".format(self)


class BaseMLSLevel(symbol.PolicySymbol):

    """Abstract base class for MLS levels."""

    def __eq__(self, other):
        try:
            othercats = set(other.categories())
        except AttributeError:
            return (str(self) == str(other))
        else:
            selfcats = set(self.categories())
            return (self.sensitivity == other.sensitivity and selfcats == othercats)

    def __ge__(self, other):
        """Dom operator."""
        selfcats = set(self.categories())
        othercats = set(other.categories())
        return (self.sensitivity >= other.sensitivity and selfcats >= othercats)

    def __gt__(self, other):
        selfcats = set(self.categories())
        othercats = set(other.categories())
        return ((self.sensitivity > other.sensitivity and selfcats >= othercats) or
                (self.sensitivity >= other.sensitivity and selfcats > othercats))

    def __le__(self, other):
        """Domby operator."""
        selfcats = set(self.categories())
        othercats = set(other.categories())
        return (self.sensitivity <= other.sensitivity and selfcats <= othercats)

    def __lt__(self, other):
        selfcats = set(self.categories())
        othercats = set(other.categories())
        return ((self.sensitivity < other.sensitivity and selfcats <= othercats) or
                (self.sensitivity <= other.sensitivity and selfcats < othercats))

    def __xor__(self, other):
        """Incomp operator."""
        return (not self >= other and not self <= other)

    def __str__(self):
        lvl = str(self.sensitivity)

        # sort by policy declaration order
        cats = sorted(self.categories(), key=lambda k: k._value)

        if cats:
            # generate short category notation
            shortlist = []
            for k, g in itertools.groupby(cats, key=lambda k,
                                          c=itertools.count(): k._value - next(c)):
                group = list(g)
                if len(group) > 1:
                    shortlist.append("{0}.{1}".format(group[0], group[-1]))
                else:
                    shortlist.append(str(group[0]))

            lvl += ":" + ','.join(shortlist)

        return lvl

    @property
    def sensitivity(self):
        raise NotImplementedError

    def categories(self):
        """
        Generator that yields all individual categories for this level.
        All categories are yielded, not a compact notation such as
        c0.c255
        """

        for cat in self.qpol_symbol.cat_iter(self.policy):
            yield category_factory(self.policy, cat)


class MLSLevelDecl(BaseMLSLevel):

    """
    The declaration statement for MLS levels, e.g:

    level s7:c0.c1023;
    """

    @property
    def sensitivity(self):
        """The sensitivity of the level."""
        # since the qpol symbol for levels is also used for
        # MLSSensitivity objects, use self's qpol symbol
        return sensitivity_factory(self.policy, self.qpol_symbol)

    def statement(self):
        return "level {0};".format(self)


class MLSLevel(BaseMLSLevel):

    """An MLS level used in contexts."""

    def __hash__(self):
        return hash(str(self))

    @property
    def sensitivity(self):
        """The sensitivity of the level."""
        return sensitivity_factory(self.policy, self.qpol_symbol.sens_name(self.policy))


class MLSRange(symbol.PolicySymbol):

    """An MLS range"""

    def __hash__(self):
        return hash(str(self))

    def __eq__(self, other):
        try:
            return (self.low == other.low and self.high == other.high)
        except AttributeError:
            o = str(other)
            if "-" in o and " - " not in o:
                raise ValueError(
                    "Range strings must have a spaces around the level separator (eg \"s0 - s1\")")

            return (str(self) == o)

    def __contains__(self, other):
        return (self.low <= other <= self.high)

    def __str__(self):
        high = self.high
        low = self.low
        if high == low:
            return str(low)

        return "{0} - {1}".format(low, high)

    @property
    def high(self):
        """The high end/clearance level of this range."""
        return level_factory(self.policy, self.qpol_symbol.high_level(self.policy))

    @property
    def low(self):
        """The low end/current level of this range."""
        return level_factory(self.policy, self.qpol_symbol.low_level(self.policy))
