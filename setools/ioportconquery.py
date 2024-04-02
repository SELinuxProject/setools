# Derived from portconquery.py
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from collections.abc import Iterable
import typing

from . import mixins, policyrep, query, util

__all__: typing.Final[tuple[str, ...]] = ("IoportconQuery",)


class IoportconQuery(mixins.MatchContext, query.PolicyQuery):

    """
    Ioportcon context query.

    Parameter:
    policy          The policy to query.

    Keyword Parameters/Class attributes:
    ports           A 2-tuple of the port range to match. (Set both to
                    the same value for a single port)
    ports_subset    If true, the criteria will match if it is a subset
                    of the ioportcon's range.
    ports_overlap   If true, the criteria will match if it overlaps
                    any of the ioportcon's range.
    ports_superset  If true, the criteria will match if it is a superset
                    of the ioportcon's range.
    ports_proper    If true, use proper superset/subset operations.
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

    _ports: policyrep.IoportconRange | None = None
    ports_subset: bool = False
    ports_overlap: bool = False
    ports_superset: bool = False
    ports_proper: bool = False

    @property
    def ports(self) -> policyrep.IoportconRange | None:
        return self._ports

    @ports.setter
    def ports(self, value: tuple[int, int] | None) -> None:
        if value:
            self._ports = policyrep.IoportconRange(*value)
        else:
            self._ports = None

    def results(self) -> Iterable[policyrep.Ioportcon]:
        """Generator which yields all matching ioportcons."""
        self.log.info(f"Generating results from {self.policy}")
        self.log.debug(f"{self.ports=}, {self.ports_overlap=}, {self.ports_subset=}, "
                       f"{self.ports_superset=}, {self.ports_proper=}")
        self._match_context_debug(self.log)

        for ioportcon in self.policy.ioportcons():

            if self.ports and not util.match_range(
                    ioportcon.ports,
                    self.ports,
                    self.ports_subset,
                    self.ports_overlap,
                    self.ports_superset,
                    self.ports_proper):
                continue

            if not self._match_context(ioportcon.context):
                continue

            yield ioportcon
