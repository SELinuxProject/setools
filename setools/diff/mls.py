# Copyright 2016, Tresys Technology, LLC
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
from .difference import SymbolWrapper, Wrapper


class LevelWrapper(Wrapper):

    """Wrap levels to allow comparisons."""

    def __init__(self, level):
        self.origin = level
        self.sensitivity = SymbolWrapper(level.sensitivity)
        self.categories = set(SymbolWrapper(c) for c in level.categories())

    def __eq__(self, other):
        return self.sensitivity == other.sensitivity and \
               self.categories == other.categories


class RangeWrapper(Wrapper):

    """
    Wrap ranges to allow comparisons.

    This only compares the low and high levels of the range.
    It does not detect additions/removals/modifications
    to levels between the low and high levels of the range.
    """

    def __init__(self, range_):
        self.origin = range_
        self.low = LevelWrapper(range_.low)
        self.high = LevelWrapper(range_.high)

    def __eq__(self, other):
        return self.low == other.low and \
               self.high == other.high
