# Copyright 2015-2016, Tresys Technology, LLC
# Copyright 2018, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: LGPL-2.1-only
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


class ConditionalWrapper(Wrapper[Conditional]):

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
