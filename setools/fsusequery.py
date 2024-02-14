# Copyright 2014-2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from typing import Iterable

from .descriptors import CriteriaDescriptor, CriteriaSetDescriptor
from .mixins import MatchContext
from .policyrep import FSUse, FSUseRuletype
from .query import PolicyQuery
from .util import match_regex


class FSUseQuery(MatchContext, PolicyQuery):

    """
    Query fs_use_* statements.

    Parameter:
    policy          The policy to query.

    Keyword Parameters/Class attributes:
    ruletype        The rule type(s) to match.
    fs              The criteria to match the file system type.
    fs_regex        If true, regular expression matching
                    will be used on the file system type.
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

    ruletype = CriteriaSetDescriptor(enum_class=FSUseRuletype)
    fs = CriteriaDescriptor("fs_regex")
    fs_regex: bool = False

    def results(self) -> Iterable[FSUse]:
        """Generator which yields all matching fs_use_* statements."""
        self.log.info("Generating fs_use_* results from {0.policy}".format(self))
        self.log.debug("Ruletypes: {0.ruletype}".format(self))
        self.log.debug("FS: {0.fs!r}, regex: {0.fs_regex}".format(self))
        self._match_context_debug(self.log)

        for fsu in self.policy.fs_uses():
            if self.ruletype and fsu.ruletype not in self.ruletype:
                continue

            if self.fs and not match_regex(
                    fsu.fs,
                    self.fs,
                    self.fs_regex):
                continue

            if not self._match_context(fsu.context):
                continue

            yield fsu
