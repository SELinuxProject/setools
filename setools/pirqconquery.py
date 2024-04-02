# Derived from portconquery.py
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from collections.abc import Iterable
import typing

from . import mixins, policyrep, query

__all__: typing.Final[tuple[str, ...]] = ("PirqconQuery",)


class PirqconQuery(mixins.MatchContext, query.PolicyQuery):

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

    _irq: int | None = None

    @property
    def irq(self) -> int | None:
        return self._irq

    @irq.setter
    def irq(self, value: int | None) -> None:
        if value:
            if value < 1:
                raise ValueError(f"The IRQ must be positive: {value}")

            self._irq = value
        else:
            self._irq = None

    def results(self) -> Iterable[policyrep.Pirqcon]:
        """Generator which yields all matching pirqcons."""
        self.log.info(f"Generating results from {self.policy}")
        self.log.debug(f"{self.irq=}")
        self._match_context_debug(self.log)

        for pirqcon in self.policy.pirqcons():

            if self.irq and self.irq != pirqcon.irq:
                continue

            if not self._match_context(pirqcon.context):
                continue

            yield pirqcon
