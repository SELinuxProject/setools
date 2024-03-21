# Derived from portconquery.py
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from typing import Iterable, Optional, Tuple

from .mixins import MatchContext
from .policyrep import Ioportcon, IoportconRange
from .query import PolicyQuery
from .util import match_range


class IoportconQuery(MatchContext, PolicyQuery):

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

    _ports: Optional[IoportconRange] = None
    ports_subset: bool = False
    ports_overlap: bool = False
    ports_superset: bool = False
    ports_proper: bool = False

    @property
    def ports(self) -> Optional[IoportconRange]:
        return self._ports

    @ports.setter
    def ports(self, value: Optional[Tuple[int, int]]) -> None:
        if value:
            pending_ports = IoportconRange(*value)
            if pending_ports.low < 1 or pending_ports.high < 1:
                raise ValueError(
                    f"Port numbers must be positive: {pending_ports.low}-{pending_ports.high}")

            if pending_ports.low > pending_ports.high:
                raise ValueError(
                    "The low port must be smaller than the high port: "
                    f"{pending_ports.low}-{pending_ports.high}")

            self._ports = pending_ports
        else:
            self._ports = None

    def results(self) -> Iterable[Ioportcon]:
        """Generator which yields all matching ioportcons."""
        self.log.info(f"Generating results from {self.policy}")
        self.log.debug(f"{self.ports=}, {self.ports_overlap=}, {self.ports_subset=}, "
                       f"{self.ports_superset=}, {self.ports_proper=}")
        self._match_context_debug(self.log)

        for ioportcon in self.policy.ioportcons():

            if self.ports and not match_range(
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
