# Copyright 2014-2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from collections.abc import Iterable
from contextlib import suppress
import typing

from . import exception, mixins, policyrep, query, util
from .descriptors import CriteriaDescriptor, CriteriaSetDescriptor

__all__: typing.Final[tuple[str, ...]] = ("ObjClassQuery",)


class ObjClassQuery(mixins.MatchName, query.PolicyQuery):

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

    common = CriteriaDescriptor[policyrep.Common]("common_regex", "lookup_common")
    common_regex: bool = False
    perms = CriteriaSetDescriptor[str]("perms_regex")
    perms_equal: bool = False
    perms_indirect: bool = True
    perms_regex: bool = False

    def results(self) -> Iterable[policyrep.ObjClass]:
        """Generator which yields all matching object classes."""
        self.log.info(f"Generating object class results from {self.policy}")
        self._match_name_debug(self.log)
        self.log.debug(f"{self.common=}, {self.common_regex=}")
        self.log.debug(f"{self.perms=}, {self.perms_regex=}, {self.perms_equal=}, "
                       f"{self.perms_indirect=}")

        for class_ in self.policy.classes():
            if not self._match_name(class_):
                continue

            if self.common:
                try:
                    if not util.match_regex(
                            class_.common,
                            self.common,
                            self.common_regex):
                        continue
                except exception.NoCommon:
                    continue

            if self.perms:
                perms = class_.perms

                if self.perms_indirect:
                    with suppress(exception.NoCommon):
                        perms |= class_.common.perms

                if not util.match_regex_or_set(
                        perms,
                        self.perms,
                        self.perms_equal,
                        self.perms_regex):
                    continue

            yield class_
