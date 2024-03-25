# Derived from portconquery.py
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from collections.abc import Iterable
import typing

from . import mixins, policyrep, query, util

__all__: typing.Final[tuple[str, ...]] = ("IomemconQuery",)


class IomemconQuery(mixins.MatchContext, query.PolicyQuery):

    """
    Iomemcon context query.

    Parameter:
    policy          The policy to query.

    Keyword Parameters/Class attributes:
    addr            A 2-tuple of the memory addr range to match. (Set both to
                    the same value for a single mem addr)
    addr_subset     If true, the criteria will match if it is a subset
                    of the iomemcon's range.
    addr_overlap    If true, the criteria will match if it overlaps
                    any of the iomemcon's range.
    addr_superset   If true, the criteria will match if it is a superset
                    of the iomemcon's range.
    addr_proper     If true, use proper superset/subset operations.
                    No effect if not using set operations.

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

    _addr: policyrep.IomemconRange | None = None
    addr_subset: bool = False
    addr_overlap: bool = False
    addr_superset: bool = False
    addr_proper: bool = False

    @property
    def addr(self) -> policyrep.IomemconRange | None:
        return self._addr

    @addr.setter
    def addr(self, value: tuple[int, int] | None) -> None:
        if value:
            self._addr = policyrep.IomemconRange(*value)
        else:
            self._addr = None

    def results(self) -> Iterable[policyrep.Iomemcon]:
        """Generator which yields all matching iomemcons."""
        self.log.info(f"Generating results from {self.policy}")
        self.log.debug(f"{self.addr=}, {self.addr_overlap=}, {self.addr_subset=}, "
                       f"{self.addr_superset=}, {self.addr_proper=}")
        self._match_context_debug(self.log)

        for iomemcon in self.policy.iomemcons():

            if self.addr and not util.match_range(
                    iomemcon.addr,
                    self.addr,
                    self.addr_subset,
                    self.addr_overlap,
                    self.addr_superset,
                    self.addr_proper):
                continue

            if not self._match_context(iomemcon.context):
                continue

            yield iomemcon
