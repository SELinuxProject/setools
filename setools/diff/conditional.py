# Copyright 2015-2016, Tresys Technology, LLC
# Copyright 2018, Chris PeBenito <pebenito@ieee.org>
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
from collections import defaultdict

from ..policyrep import Conditional

from .difference import Wrapper
from .typing import Cache


_cond_cache: Cache[Conditional, "ConditionalWrapper"] = defaultdict(dict)


def conditional_wrapper_factory(cond: Conditional) -> "ConditionalWrapper":
    """
    Wrap type attributes from the specified policy.

    This caches results to prevent duplicate wrapper
    objects in memory.
    """
    try:
        return _cond_cache[cond.policy][cond]
    except KeyError:
        a = ConditionalWrapper(cond)
        _cond_cache[cond.policy][cond] = a
        return a


# Pylint bug: https://github.com/PyCQA/pylint/issues/2822
class ConditionalWrapper(Wrapper[Conditional]):  # pylint: disable=unsubscriptable-object

    """Wrap conditional policy expressions to allow comparisons by truth table."""

    __slots__ = ("truth_table")

    def __init__(self, cond: Conditional) -> None:
        self.origin = cond
        self.truth_table = cond.truth_table()

    def __hash__(self):
        return hash(self.origin)

    def __eq__(self, other):
        return self.truth_table == other.truth_table

    def __lt__(self, other):
        return str(self.origin) < str(other)
