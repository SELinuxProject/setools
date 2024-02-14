# Derived from portconquery.py
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from typing import Iterable, Optional

from .mixins import MatchContext
from .policyrep import Pcidevicecon
from .query import PolicyQuery


class PcideviceconQuery(MatchContext, PolicyQuery):

    """
    Pcidevicecon context query.

    Parameter:
    policy          The policy to query.

    Keyword Parameters/Class attributes:
    device          A single PCI device ID.

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

    _device: Optional[int] = None

    @property
    def device(self) -> Optional[int]:
        return self._device

    @device.setter
    def device(self, value: Optional[int]) -> None:
        if value:
            if value < 1:
                raise ValueError("PCI device ID must be positive: {0}".format(value))

            self._device = value
        else:
            self._device = None

    def results(self) -> Iterable[Pcidevicecon]:
        """Generator which yields all matching pcidevicecons."""
        self.log.info("Generating results from {0.policy}".format(self))
        self.log.debug("Device ID: {0.device!r}".format(self))
        self._match_context_debug(self.log)

        for pcidevicecon in self.policy.pcidevicecons():

            if self.device and self.device != pcidevicecon.device:
                continue

            if not self._match_context(pcidevicecon.context):
                continue

            yield pcidevicecon
