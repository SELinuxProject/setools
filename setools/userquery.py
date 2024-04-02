# Copyright 2014-2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from collections.abc import Iterable
import typing

from . import mixins, policyrep, query, util
from .descriptors import CriteriaDescriptor, CriteriaSetDescriptor

__all__: typing.Final[tuple[str, ...]] = ("UserQuery",)


class UserQuery(mixins.MatchName, query.PolicyQuery):

    """
    Query SELinux policy users.

    Parameter:
    policy            The policy to query.

    Keyword Parameters/Class attributes:
    name            The user name to match.
    name_regex      If true, regular expression matching
                    will be used on the user names.
    roles           The attribute to match.
    roles_equal     If true, only types with role sets
                    that are equal to the criteria will
                    match.  Otherwise, any intersection
                    will match.
    roles_regex     If true, regular expression matching
                    will be used on the role names instead
                    of set logic.
    level           The criteria to match the user's default level.
    level_dom       If true, the criteria will match if it dominates
                    the user's default level.
    level_domby     If true, the criteria will match if it is dominated
                    by the user's default level.
    level_incomp    If true, the criteria will match if it is incomparable
                    to the user's default level.
    range_          The criteria to match the user's range.
    range_subset    If true, the criteria will match if it is a subset
                    of the user's range.
    range_overlap   If true, the criteria will match if it overlaps
                    any of the user's range.
    range_superset  If true, the criteria will match if it is a superset
                    of the user's range.
    range_proper    If true, use proper superset/subset operations.
                    No effect if not using set operations.
    """

    level = CriteriaDescriptor[policyrep.Level](lookup_function="lookup_level")
    level_dom: bool = False
    level_domby: bool = False
    level_incomp: bool = False
    range_ = CriteriaDescriptor[policyrep.Range](lookup_function="lookup_range")
    range_overlap: bool = False
    range_subset: bool = False
    range_superset: bool = False
    range_proper: bool = False
    roles = CriteriaSetDescriptor[policyrep.Role]("roles_regex", "lookup_role")
    roles_equal: bool = False
    roles_regex: bool = False

    def results(self) -> Iterable[policyrep.User]:
        """Generator which yields all matching users."""
        self.log.info(f"Generating user results from {self.policy}")
        self._match_name_debug(self.log)
        self.log.debug(f"{self.roles=}, {self.roles_regex=}, {self.roles_equal=}")
        self.log.debug(f"{self.level=}, {self.level_dom=}, {self.level_domby=}, "
                       f"{self.level_incomp=}")
        self.log.debug(f"{self.range_=}, {self.range_subset=}, {self.range_overlap=}, "
                       f"{self.range_superset=}, {self.range_proper=}")

        for user in self.policy.users():
            if not self._match_name(user):
                continue

            if self.roles and not util.match_regex_or_set(
                    user.roles,
                    self.roles,
                    self.roles_equal,
                    self.roles_regex):
                continue

            if self.level and not util.match_level(
                    user.mls_level,
                    self.level,
                    self.level_dom,
                    self.level_domby,
                    self.level_incomp):
                continue

            if self.range_ and not util.match_range(
                    user.mls_range,
                    self.range_,
                    self.range_subset,
                    self.range_overlap,
                    self.range_superset,
                    self.range_proper):
                continue

            yield user
