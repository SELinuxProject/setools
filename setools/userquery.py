# Copyright 2014-2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
import logging
import re
from typing import Iterable

from .descriptors import CriteriaDescriptor, CriteriaSetDescriptor
from .mixins import MatchName
from .policyrep import User
from .query import PolicyQuery
from .util import match_regex_or_set, match_level, match_range


class UserQuery(MatchName, PolicyQuery):

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

    level = CriteriaDescriptor(lookup_function="lookup_level")
    level_dom: bool = False
    level_domby: bool = False
    level_incomp: bool = False
    range_ = CriteriaDescriptor(lookup_function="lookup_range")
    range_overlap: bool = False
    range_subset: bool = False
    range_superset: bool = False
    range_proper: bool = False
    roles = CriteriaSetDescriptor("roles_regex", "lookup_role")
    roles_equal: bool = False
    roles_regex: bool = False

    def __init__(self, policy, **kwargs) -> None:
        super(UserQuery, self).__init__(policy, **kwargs)
        self.log = logging.getLogger(__name__)

    def results(self) -> Iterable[User]:
        """Generator which yields all matching users."""
        self.log.info("Generating user results from {0.policy}".format(self))
        self._match_name_debug(self.log)
        self.log.debug("Roles: {0.roles!r}, regex: {0.roles_regex}, "
                       "eq: {0.roles_equal}".format(self))
        self.log.debug("Level: {0.level!r}, dom: {0.level_dom}, domby: {0.level_domby}, "
                       "incomp: {0.level_incomp}".format(self))
        self.log.debug("Range: {0.range_!r}, subset: {0.range_subset}, overlap: {0.range_overlap}, "
                       "superset: {0.range_superset}, proper: {0.range_proper}".format(self))

        for user in self.policy.users():
            if not self._match_name(user):
                continue

            if self.roles and not match_regex_or_set(
                    user.roles,
                    self.roles,
                    self.roles_equal,
                    self.roles_regex):
                continue

            if self.level and not match_level(
                    user.mls_level,
                    self.level,
                    self.level_dom,
                    self.level_domby,
                    self.level_incomp):
                continue

            if self.range_ and not match_range(
                    user.mls_range,
                    self.range_,
                    self.range_subset,
                    self.range_overlap,
                    self.range_superset,
                    self.range_proper):
                continue

            yield user
