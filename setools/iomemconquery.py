# Derived from portconquery.py
#
# This file is part of SETools.
#
# SETools is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation, either version 2.1 of
# the License, or (at your option) any later version.
#
# SETools is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with SETools.  If not, see
# <http://www.gnu.org/licenses/>.
#
import logging

from . import contextquery
from .policyrep.xencontext import addr_range


class IomemconQuery(contextquery.ContextQuery):

    """
    Iomemcon context query.

    Parameter:
    policy          The policy to query.

    Keyword Parameters/Class attributes:
    mem_addr           A 2-tuple of the memory addr range to match. (Set both to
                    the same value for a single mem addr)
    mem_addr_subset    If true, the criteria will match if it is a subset
                    of the iomemcon's range.
    mem_addr_overlap   If true, the criteria will match if it overlaps
                    any of the iomemcon's range.
    mem_addr_superset  If true, the criteria will match if it is a superset
                    of the iomemcon's range.
    mem_addr_proper    If true, use proper superset/subset operations.
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

    _mem_addr = None
    mem_addr_subset = False
    mem_addr_overlap = False
    mem_addr_superset = False
    mem_addr_proper = False

    @property
    def mem_addr(self):
        return self._mem_addr

    @mem_addr.setter
    def mem_addr(self, value):
        pending_mem_addr = addr_range(*value)

        if all(pending_mem_addr):
            if pending_mem_addr.low < 1 or pending_mem_addr.high < 1:
                raise ValueError("Memory address must be positive: {0.low}-{0.high}".
                                 format(pending_mem_addr))

            if pending_mem_addr.low > pending_mem_addr.high:
                raise ValueError(
                    "The low mem addr must be smaller than the high mem addr: {0.low}-{0.high}".
                    format(pending_mem_addr))

            self._mem_addr = pending_mem_addr
        else:
            self._mem_addr = None

    def results(self):
        """Generator which yields all matching iomemcons."""
        self.log.info("Generating results from {0.policy}".format(self))
        self.log.debug("mem_addr: {0.mem_addr}, overlap: {0.mem_addr_overlap}, "
                       "subset: {0.mem_addr_subset}, superset: {0.mem_addr_superset}, "
                       "proper: {0.mem_addr_proper}".format(self))
        self.log.debug("User: {0.user!r}, regex: {0.user_regex}".format(self))
        self.log.debug("Role: {0.role!r}, regex: {0.role_regex}".format(self))
        self.log.debug("Type: {0.type_!r}, regex: {0.type_regex}".format(self))
        self.log.debug("Range: {0.range_!r}, subset: {0.range_subset}, overlap: {0.range_overlap}, "
                       "superset: {0.range_superset}, proper: {0.range_proper}".format(self))

        for iomemcon in self.policy.iomemcons():

            if self.mem_addr and not self._match_range(
                    iomemcon.mem_addr,
                    self.mem_addr,
                    self.mem_addr_subset,
                    self.mem_addr_overlap,
                    self.mem_addr_superset,
                    self.mem_addr_proper):
                continue

            if not self._match_context(iomemcon.context):
                continue
            yield iomemcon
