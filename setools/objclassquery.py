# Copyright 2014-2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from contextlib import suppress
from typing import Iterable

from .descriptors import CriteriaDescriptor, CriteriaSetDescriptor
from .exception import NoCommon
from .mixins import MatchName
from .policyrep import ObjClass
from .query import PolicyQuery
from .util import match_regex, match_regex_or_set


class ObjClassQuery(MatchName, PolicyQuery):

    """
    Query object classes.

    Parameter:
    policy          The policy to query.

    Keyword Parameters/Class attributes:
    name            The name of the object set to match.
    name_regex      If true, regular expression matching will
                    be used for matching the name.
    common          The name of the inherited common to match.
    common_regex    If true, regular expression matching will
                    be used for matching the common name.
    perms           The permissions to match.
    perms_equal     If true, only commons with permission sets
                    that are equal to the criteria will
                    match.  Otherwise, any intersection
                    will match.
    perms_regex     If true, regular expression matching
                    will be used on the permission names instead
                    of set logic.
                    comparison will not be used.
    perms_indirect  If false, permissions inherited from a common
                    permission set not will be evaluated.  Default
                    is true.
    """

    common = CriteriaDescriptor("common_regex", "lookup_common")
    common_regex: bool = False
    perms = CriteriaSetDescriptor("perms_regex")
    perms_equal: bool = False
    perms_indirect: bool = True
    perms_regex: bool = False

    def results(self) -> Iterable[ObjClass]:
        """Generator which yields all matching object classes."""
        self.log.info("Generating object class results from {0.policy}".format(self))
        self._match_name_debug(self.log)
        self.log.debug("Common: {0.common!r}, regex: {0.common_regex}".format(self))
        self.log.debug("Perms: {0.perms}, regex: {0.perms_regex}, "
                       "eq: {0.perms_equal}, indirect: {0.perms_indirect}".format(self))

        for class_ in self.policy.classes():
            if not self._match_name(class_):
                continue

            if self.common:
                try:
                    if not match_regex(
                            class_.common,
                            self.common,
                            self.common_regex):
                        continue
                except NoCommon:
                    continue

            if self.perms:
                perms = class_.perms

                if self.perms_indirect:
                    with suppress(NoCommon):
                        perms |= class_.common.perms

                if not match_regex_or_set(
                        perms,
                        self.perms,
                        self.perms_equal,
                        self.perms_regex):
                    continue

            yield class_
