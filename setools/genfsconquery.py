# Copyright 2014-2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from collections.abc import Iterable
import typing

from . import mixins, policyrep, query, util
from .descriptors import CriteriaDescriptor

__all__: typing.Final[tuple[str, ...]] = ("GenfsconQuery",)


class GenfsconQuery(mixins.MatchContext, query.PolicyQuery):

    """
    Query genfscon statements.

    Parameter:
    policy          The policy to query.

    Keyword Parameters/Class attributes:
    fs              The criteria to match the file system type.
    fs_regex        If true, regular expression matching
                    will be used on the file system type.
    path            The criteria to match the path.
    path_regex      If true, regular expression matching
                    will be used on the path.
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

    filetype: int | None = None
    fs = CriteriaDescriptor[str]("fs_regex")
    fs_regex: bool = False
    path = CriteriaDescriptor[str]("path_regex")
    path_regex: bool = False

    def results(self) -> Iterable[policyrep.Genfscon]:
        """Generator which yields all matching genfscons."""
        self.log.info(f"Generating genfscon results from {self.policy}")
        self.log.debug(f"{self.fs=}, {self.fs_regex=}")
        self.log.debug(f"{self.path=}, {self.path_regex=}")
        self.log.debug(f"{self.filetype=}")
        self._match_context_debug(self.log)

        for genfs in self.policy.genfscons():
            if self.fs and not util.match_regex(
                    genfs.fs,
                    self.fs,
                    self.fs_regex):
                continue

            if self.path and not util.match_regex(
                    genfs.path,
                    self.path,
                    self.path_regex):
                continue

            if self.filetype and not self.filetype == genfs.filetype:
                continue

            if not self._match_context(genfs.context):
                continue

            yield genfs
