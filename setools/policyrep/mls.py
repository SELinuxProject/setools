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
# pylint: disable=protected-access
import itertools

from . import exception
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


def enabled(policy):
    """Determine if MLS is enabled."""
    return policy.capability(qpol.QPOL_CAP_MLS)


def category_factory(policy, sym):
    """Factory function for creating MLS category objects."""

    if not enabled(policy):
        raise exception.MLSDisabled

    if isinstance(sym, Category):
        assert sym.policy == policy
        return sym
    elif isinstance(sym, qpol.qpol_cat_t):
        if sym.isalias(policy):
            raise TypeError("{0} is an alias".format(sym.name(policy)))

        return Category(policy, sym)

    try:
        return Category(policy, qpol.qpol_cat_t(policy, str(sym)))
    except ValueError:
        raise exception.InvalidCategory("{0} is not a valid category".format(sym))


def sensitivity_factory(policy, sym):
    """Factory function for creating MLS sensitivity objects."""

    if not enabled(policy):
        raise exception.MLSDisabled

    if isinstance(sym, Sensitivity):
        assert sym.policy == policy
        return sym
    elif isinstance(sym, qpol.qpol_level_t):
        if sym.isalias(policy):
            raise TypeError("{0} is an alias".format(sym.name(policy)))

        return Sensitivity(policy, sym)

    try:
        return Sensitivity(policy, qpol.qpol_level_t(policy, str(sym)))
    except ValueError:
        raise exception.InvalidSensitivity("{0} is not a valid sensitivity".format(sym))


def level_factory(policy, sym):
    """
    Factory function for creating MLS level objects (e.g. levels used
    in contexts of labeling statements)
    """

    if not enabled(policy):
        raise exception.MLSDisabled

    if isinstance(sym, Level):
        assert sym.policy == policy
        return sym
    elif isinstance(sym, qpol.qpol_mls_level_t):
        return Level(policy, sym)

    sens_split = str(sym).split(":")

    sens = sens_split[0]
    try:
        semantic_level = qpol.qpol_semantic_level_t(policy, sens)
    except ValueError:
        raise exception.InvalidLevel("{0} is invalid ({1} is not a valid sensitivity)".
                                     format(sym, sens))

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
                    raise exception.InvalidLevel(
                        "{0} is invalid ({1} is not a valid category range)".format(sym, group))
            elif len(catrange) == 1:
                try:
                    semantic_level.add_cats(policy, catrange[0], catrange[0])
                except ValueError:
                    raise exception.InvalidLevel("{0} is invalid  ({1} is not a valid category)".
                                                 format(sym, group))
            else:
                raise exception.InvalidLevel("{0} is invalid (level parsing error)".format(sym))

    # convert to level object
    try:
        policy_level = qpol.qpol_mls_level_t(policy, semantic_level)
    except ValueError:
        raise exception.InvalidLevel(
            "{0} is invalid (one or more categories are not associated with the sensitivity)".
            format(sym))

    return Level(policy, policy_level)


def level_decl_factory(policy, sym):
    """
    Factory function for creating MLS level declaration objects.
    (level statements) Lookups are only by sensitivity name.
    """

    if not enabled(policy):
        raise exception.MLSDisabled

    if isinstance(sym, LevelDecl):
        assert sym.policy == policy
        return sym
    elif isinstance(sym, qpol.qpol_level_t):
        if sym.isalias(policy):
            raise TypeError("{0} is an alias".format(sym.name(policy)))

        return LevelDecl(policy, sym)

    try:
        return LevelDecl(policy, qpol.qpol_level_t(policy, str(sym)))
    except ValueError:
        raise exception.InvalidLevelDecl("{0} is not a valid sensitivity".format(sym))


def range_factory(policy, sym):
    """Factory function for creating MLS range objects."""

    if not enabled(policy):
        raise exception.MLSDisabled

    if isinstance(sym, Range):
        assert sym.policy == policy
        return sym
    elif isinstance(sym, qpol.qpol_mls_range_t):
        return Range(policy, sym)

    # build range:
    levels = str(sym).split("-")

    # strip() levels to handle ranges with spaces in them,
    # e.g. s0:c1 - s0:c0.c255
    try:
        low = level_factory(policy, levels[0].strip())
    except exception.InvalidLevel as ex:
        raise exception.InvalidRange("{0} is not a valid range ({1}).".format(sym, ex))

    try:
        high = level_factory(policy, levels[1].strip())
    except exception.InvalidLevel as ex:
        raise exception.InvalidRange("{0} is not a valid range ({1}).".format(sym, ex))
    except IndexError:
        high = low

    # convert to range object
    try:
        policy_range = qpol.qpol_mls_range_t(policy, low.qpol_symbol, high.qpol_symbol)
    except ValueError:
        raise exception.InvalidRange("{0} is not a valid range ({1} is not dominated by {2})".
                                     format(sym, low, high))

    return Range(policy, policy_range)


class BaseMLSComponent(symbol.PolicySymbol):

    """Base class for sensitivities and categories."""

    @property
    def _value(self):
        """
        The value of the component.

        This is a low-level policy detail exposed for internal use only.
        """
        return self.qpol_symbol.value(self.policy)

    def aliases(self):
        """Generator that yields all aliases for this category."""

        for alias in self.qpol_symbol.alias_iter(self.policy):
            yield alias


class Category(BaseMLSComponent):

    """An MLS category."""

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


class Sensitivity(BaseMLSComponent):

    """An MLS sensitivity"""

    def __eq__(self, other):
        try:
            return self._value == other._value
        except AttributeError:
            return str(self) == str(other)

    def __ge__(self, other):
        return self._value >= other._value

    def __gt__(self, other):
        return self._value > other._value

    def __le__(self, other):
        return self._value <= other._value

    def __lt__(self, other):
        return self._value < other._value

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


class BaseMLSLevel(symbol.PolicySymbol):

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


class LevelDecl(BaseMLSLevel):

    """
    The declaration statement for MLS levels, e.g:

    level s7:c0.c1023;
    """
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

    @property
    def sensitivity(self):
        """The sensitivity of the level."""
        # since the qpol symbol for levels is also used for
        # MLSSensitivity objects, use self's qpol symbol
        return sensitivity_factory(self.policy, self.qpol_symbol)

    def statement(self):
        return "level {0};".format(self)


class Level(BaseMLSLevel):

    """An MLS level used in contexts."""

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
        """Dom operator."""
        selfcats = set(self.categories())
        othercats = set(other.categories())
        return self.sensitivity >= other.sensitivity and selfcats >= othercats

    def __gt__(self, other):
        selfcats = set(self.categories())
        othercats = set(other.categories())
        return ((self.sensitivity > other.sensitivity and selfcats >= othercats) or
                (self.sensitivity >= other.sensitivity and selfcats > othercats))

    def __le__(self, other):
        """Domby operator."""
        selfcats = set(self.categories())
        othercats = set(other.categories())
        return self.sensitivity <= other.sensitivity and selfcats <= othercats

    def __lt__(self, other):
        selfcats = set(self.categories())
        othercats = set(other.categories())
        return ((self.sensitivity < other.sensitivity and selfcats <= othercats) or
                (self.sensitivity <= other.sensitivity and selfcats < othercats))

    def __xor__(self, other):
        """Incomp operator."""
        return not (self >= other or self <= other)

    @property
    def sensitivity(self):
        """The sensitivity of the level."""
        return sensitivity_factory(self.policy, self.qpol_symbol.sens_name(self.policy))

    def statement(self):
        raise exception.NoStatement


class Range(symbol.PolicySymbol):

    """An MLS range"""

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

    @property
    def high(self):
        """The high end/clearance level of this range."""
        return level_factory(self.policy, self.qpol_symbol.high_level(self.policy))

    @property
    def low(self):
        """The low end/current level of this range."""
        return level_factory(self.policy, self.qpol_symbol.low_level(self.policy))

    def statement(self):
        raise exception.NoStatement
