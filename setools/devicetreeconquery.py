# Derived from portconquery.py
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from collections.abc import Iterable
import typing

from . import mixins, policyrep, query

__all__: typing.Final[tuple[str, ...]] = ("DevicetreeconQuery",)


class DevicetreeconQuery(mixins.MatchContext, query.PolicyQuery):

    """
    Devicetreecon context query.

    Parameter:
    policy          The policy to query.

    Keyword Parameters/Class attributes:
    path             A single devicetree path.

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

    path: str | None = None

    def results(self) -> Iterable[policyrep.Devicetreecon]:
        """Generator which yields all matching devicetreecons."""
        self.log.info(f"Generating results from {self.policy}")
        self.log.debug(f"{self.path=}")
        self._match_context_debug(self.log)

        for devicetreecon in self.policy.devicetreecons():

            if self.path and self.path != devicetreecon.path:
                continue

            if not self._match_context(devicetreecon.context):
                continue

            yield devicetreecon
