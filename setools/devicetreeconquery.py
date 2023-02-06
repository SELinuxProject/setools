# Derived from portconquery.py
#
# SPDX-License-Identifier: LGPL-2.1-only
#
import logging
from typing import Iterable, Optional

from .mixins import MatchContext
from .policyrep import Devicetreecon
from .query import PolicyQuery


class DevicetreeconQuery(MatchContext, PolicyQuery):

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

    path: Optional[str] = None

    def __init__(self, policy, **kwargs) -> None:
        super(DevicetreeconQuery, self).__init__(policy, **kwargs)
        self.log = logging.getLogger(__name__)

    def results(self) -> Iterable[Devicetreecon]:
        """Generator which yields all matching devicetreecons."""
        self.log.info("Generating results from {0.policy}".format(self))
        self.log.debug("Path: {0.path!r}".format(self))
        self._match_context_debug(self.log)

        for devicetreecon in self.policy.devicetreecons():

            if self.path and self.path != devicetreecon.path:
                continue

            if not self._match_context(devicetreecon.context):
                continue

            yield devicetreecon
