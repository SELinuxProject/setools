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
import itertools
import string

import qpol
import symbol


class MLSDisabled(symbol.InvalidSymbol):

    """
    Exception when MLS is disabled.
    """
    pass


class MLSCategory(symbol.PolicySymbol):

    """An MLS category."""

    @property
    def isalias(self):
        """(T/F) this is an alias."""
        return self.qpol_symbol.isalias(self.policy)

    @property
    def value(self):
        """
        The value of the category.

        This is a low-level policy detail exposed so that categories can
        be sorted based on their policy declaration order instead of
        by their name.  This has no other use.

        Example usage: sorted(self.categories(), key=lambda k: k.value)
        """
        return self.qpol_symbol.value(self.policy)

    def aliases(self):
        """Generator that yields all aliases for this category."""

        aiter = self.qpol_symbol.alias_iter(self.policy)
        while not aiter.isend():
            yield qpol.to_str(aiter.item())
            aiter.next()

# libqpol does not expose sensitivities as an individual component


class MLSSensitivity(symbol.PolicySymbol):
    pass


class MLSLevel(symbol.PolicySymbol):

    """An MLS level."""

    def __eq__(self, other):
        if self.policy == other.policy:
            if (self.qpol_symbol.sens_name(self.policy) != other.qpol_symbol.get_sens_name(self.policy)):
                return False

            selfcats = set(str(c) for c in self.categories())
            othercats = set(str(c) for c in other.categories())
            return (not selfcats ^ othercats)

        else:
            raise NotImplementedError

    def __str__(self):
        lvl = str(self.qpol_symbol.sens_name(self.policy))

        # sort by policy declaration order
        cats = sorted(self.categories(), key=lambda k: k.value)

        if cats:
            # generate short category notation
            shortlist = []
            for k, g in itertools.groupby(cats, key=lambda k, c=itertools.count(): k.value - next(c)):
                group = list(g)
                if len(group) > 1:
                    shortlist.append("{0}.{1}".format(group[0], group[-1]))
                else:
                    shortlist.append(str(group[0]))

            lvl += ":" + string.join(shortlist, ",")

        return lvl

    def categories(self):
        """
        Generator that yields all individual categories for this level.
        All categories are yielded, not a compact notation such as
        c0.c255
        """

        citer = self.qpol_symbol.cat_iter(self.policy)
        while not citer.isend():
            yield MLSCategory(self.policy, qpol.qpol_cat_from_void(citer.item()))
            citer.next()


class MLSRange(symbol.PolicySymbol):

    """An MLS range"""

    def __str__(self):
        high = self.high
        low = self.low
        if high == low:
            return str(low)

        return "{0} - {1}".format(low, high)

    @property
    def high(self):
        """The high end/clearance level of this range."""
        return MLSLevel(self.policy, self.qpol_symbol.high_level(self.policy))

    @property
    def low(self):
        """The low end/current level of this range."""
        return MLSLevel(self.policy, self.qpol_symbol.low_level(self.policy))
