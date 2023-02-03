# Copyright 2018, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: LGPL-2.1-only
#
import logging
from typing import Iterable, Optional

from .mixins import MatchContext, MatchName
from .policyrep import Ibendportcon
from .query import PolicyQuery
from .util import match_regex


class IbendportconQuery(MatchContext, MatchName, PolicyQuery):

    """
    Infiniband endport context query.

    Parameter:
    policy          The policy to query.

    Keyword Parameters/Class attributes:
    name            The name of the network interface to match.
    name_regex      If true, regular expression matching will
                    be used for matching the name.
    port            The port number to match.
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

    _port: Optional[int] = None

    @property
    def port(self) -> Optional[int]:
        return self._port

    @port.setter
    def port(self, value: Optional[int]) -> None:
        if value:
            pending_value = int(value)
            if not 0 < pending_value < 256:
                raise ValueError("Endport value must be 1-255.")

            self._port = pending_value
        else:
            self._port = None

    def __init__(self, policy, **kwargs):
        super(IbendportconQuery, self).__init__(policy, **kwargs)
        self.log = logging.getLogger(__name__)

    def results(self) -> Iterable[Ibendportcon]:
        """Generator which yields all matching ibendportcons."""
        self.log.info("Generating ibendportcon results from {0.policy}".format(self))
        self._match_name_debug(self.log)
        self.log.debug("Port: {0.port!r}".format(self))
        self._match_context_debug(self.log)

        for endport in self.policy.ibendportcons():
            if self.name and not match_regex(
                    endport.name,
                    self.name,
                    self.name_regex):
                continue

            if self.port is not None and self.port != endport.port:
                continue

            if not self._match_context(endport.context):
                continue

            yield endport
