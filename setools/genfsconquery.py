# Copyright 2014-2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
import logging
import re
from typing import Iterable, Optional

from .descriptors import CriteriaDescriptor
from .mixins import MatchContext
from .policyrep import Genfscon
from .query import PolicyQuery
from .util import match_regex


class GenfsconQuery(MatchContext, PolicyQuery):

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

    filetype: Optional[int] = None
    fs = CriteriaDescriptor("fs_regex")
    fs_regex: bool = False
    path = CriteriaDescriptor("path_regex")
    path_regex: bool = False

    def __init__(self, policy, **kwargs) -> None:
        super(GenfsconQuery, self).__init__(policy, **kwargs)
        self.log = logging.getLogger(__name__)

    def results(self) -> Iterable[Genfscon]:
        """Generator which yields all matching genfscons."""
        self.log.info("Generating genfscon results from {0.policy}".format(self))
        self.log.debug("FS: {0.fs!r}, regex: {0.fs_regex}".format(self))
        self.log.debug("Path: {0.path!r}, regex: {0.path_regex}".format(self))
        self.log.debug("Filetype: {0.filetype!r}".format(self))
        self._match_context_debug(self.log)

        for genfs in self.policy.genfscons():
            if self.fs and not match_regex(
                    genfs.fs,
                    self.fs,
                    self.fs_regex):
                continue

            if self.path and not match_regex(
                    genfs.path,
                    self.path,
                    self.path_regex):
                continue

            if self.filetype and not self.filetype == genfs.filetype:
                continue

            if not self._match_context(genfs.context):
                continue

            yield genfs
