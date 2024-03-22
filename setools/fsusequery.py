# Copyright 2014-2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from collections.abc import Iterable
import typing

from . import mixins, policyrep, query, util
from .descriptors import CriteriaDescriptor, CriteriaSetDescriptor

__all__: typing.Final[tuple[str, ...]] = ("FSUseQuery",)


class FSUseQuery(mixins.MatchContext, query.PolicyQuery):

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

    ruletype = CriteriaSetDescriptor[policyrep.FSUseRuletype](enum_class=policyrep.FSUseRuletype)
    fs = CriteriaDescriptor[str]("fs_regex")
    fs_regex: bool = False

    def results(self) -> Iterable[policyrep.FSUse]:
        """Generator which yields all matching fs_use_* statements."""
        self.log.info(f"Generating fs_use_* results from {self.policy}")
        self.log.debug(f"{self.ruletype=}")
        self.log.debug(f"{self.fs=}, {self.fs_regex=}")
        self._match_context_debug(self.log)

        for fsu in self.policy.fs_uses():
            if self.ruletype and fsu.ruletype not in self.ruletype:
                continue

            if self.fs and not util.match_regex(
                    fsu.fs,
                    self.fs,
                    self.fs_regex):
                continue

            if not self._match_context(fsu.context):
                continue

            yield fsu
