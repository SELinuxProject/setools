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


class MLSCategory(symbol.PolicySymbol):

    """An MLS category."""

    @property
    def isalias(self):
        """(T/F) this is an alias."""
        return self.qpol_symbol.get_isalias(self.policy)

    def aliases(self):
        """Generator that yields all aliases for this category."""

        aiter = self.qpol_symbol.get_alias_iter(self.policy)
        while not aiter.end():
            yield qpol.to_str(aiter.get_item())
            aiter.next()

# libqpol does not expose sensitivities as an individual component
class MLSSensitivity(symbol.PolicySymbol):
    pass


class MLSLevel(symbol.PolicySymbol):

    """An MLS level."""

    def __str__(self):
        # TODO: add compact category notation
        return self.qpol_symbol.get_sens_name(self.policy)

    def categories(self):
        """
        Generator that yields all individual categories for this level.
        All categories are yielded, not a compact notation such as
        c0.c255
        """

        citer = self.qpol_symbol.get_cat_iter(self.policy)
        while not citer.end():
            yield MLSCategory(self.policy, qpol.qpol_cat_from_void(citer.get_item()))
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
        return MLSLevel(self.policy, self.qpol_symbol.get_high_level(self.policy))

    @property
    def low(self):
        """The low end/current level of this range."""
        return MLSLevel(self.policy, self.qpol_symbol.get_low_level(self.policy))
