# Derived from portconquery.py
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from typing import Iterable, Optional

from .mixins import MatchContext
from .policyrep import Pirqcon
from .query import PolicyQuery


class PirqconQuery(MatchContext, PolicyQuery):

    """
    Pirqcon context query.

    Parameter:
    policy          The policy to query.

    Keyword Parameters/Class attributes:
    irq             A single IRQ value.

    user            The criteria to match the context's user.
    user_regex      If true, regular expression matching
                    will be used on the user.

    role            The criteria to match the context's role.
    role_regex      If true, regular expression matching
                    will be used on the role.

    type_           The criteria to match the context's type.
    type_regex      If true, regular expression matching
                    will be used on the type.

    range_          The criteria to match the context's range.
    range_subset    If true, the criteria will match if it is a subset
                    of the context's range.
    range_overlap   If true, the criteria will match if it overlaps
                    any of the context's range.
    range_superset  If true, the criteria will match if it is a superset
                    of the context's range.
    range_proper    If true, use proper superset/subset operations.
                    No effect if not using set operations.
    """

    _irq: Optional[int] = None

    @property
    def irq(self) -> Optional[int]:
        return self._irq

    @irq.setter
    def irq(self, value: Optional[int]) -> None:
        if value:
            if value < 1:
                raise ValueError("The IRQ must be positive: {0}".format(value))

            self._irq = value
        else:
            self._irq = None

    def results(self) -> Iterable[Pirqcon]:
        """Generator which yields all matching pirqcons."""
        self.log.info("Generating results from {0.policy}".format(self))
        self.log.debug("IRQ: {0.irq!r}".format(self))
        self._match_context_debug(self.log)

        for pirqcon in self.policy.pirqcons():

            if self.irq and self.irq != pirqcon.irq:
                continue

            if not self._match_context(pirqcon.context):
                continue

            yield pirqcon
