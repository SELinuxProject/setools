# Copyright 2016, Tresys Technology, LLC
# Copyright 2018, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from collections import defaultdict
from dataclasses import dataclass

from ..exception import MLSDisabled
from ..policyrep import Level, Range, Role, User

from .descriptors import DiffResultDescriptor
from .difference import Difference, DifferenceResult, SymbolWrapper
from .mls import LevelWrapper, RangeWrapper
from .roles import role_wrapper_factory
from .typing import SymbolCache

_users_cache: SymbolCache[User] = defaultdict(dict)


@dataclass(frozen=True, order=True)
class ModifiedUser(DifferenceResult):

    """Difference details for a modified user."""

    user: User
    added_roles: set[Role]
    removed_roles: set[Role]
    matched_roles: set[Role]
    added_level: Level | str | None
    removed_level: Level | str | None
    added_range: Range | str | None
    removed_range: Range | str | None


def user_wrapper_factory(user: User) -> SymbolWrapper[User]:
    """
    Wrap users from the specified policy.

    This caches results to prevent duplicate wrapper
    objects in memory.
    """
    try:
        return _users_cache[user.policy][user]
    except KeyError:
        r = SymbolWrapper(user)
        _users_cache[user.policy][user] = r
        return r


class UsersDifference(Difference):

    """Determine the difference in users between two policies."""

    def diff_users(self) -> None:
        """Generate the difference in users between the policies."""

        self.log.info(
            f"Generating user differences from {self.left_policy} to {self.right_policy}")

        self.added_users, self.removed_users, matched_users = self._set_diff(
            (user_wrapper_factory(r) for r in self.left_policy.users()),
            (user_wrapper_factory(r) for r in self.right_policy.users()))

        self.modified_users = list[ModifiedUser]()

        for left_user, right_user in matched_users:
            # Criteria for modified users
            # 1. change to role set, or
            # 2. change to default level, or
            # 3. change to range
            added_roles, removed_roles, matched_roles = self._set_diff(
                (role_wrapper_factory(r) for r in left_user.roles),
                (role_wrapper_factory(r) for r in right_user.roles))

            # keep wrapped and unwrapped MLS objects here so there
            # are not several nested try blocks
            left_level_wrap: LevelWrapper | None
            left_range_wrap: RangeWrapper | None
            left_level: Level | str
            left_range: Range | str
            right_level_wrap: LevelWrapper | None
            right_range_wrap: RangeWrapper | None
            right_level: Level | str
            right_range: Range | str
            added_level: Level | str | None
            added_range: Range | str | None
            removed_level: Level | str | None
            removed_range: Range | str | None
            try:
                left_level_wrap = LevelWrapper(left_user.mls_level)
                left_range_wrap = RangeWrapper(left_user.mls_range)
                left_level = left_user.mls_level
                left_range = left_user.mls_range
            except MLSDisabled:
                left_level_wrap = None
                left_range_wrap = None
                left_level = "None (MLS Disabled)"
                left_range = "None (MLS Disabled)"

            try:
                right_level_wrap = LevelWrapper(right_user.mls_level)
                right_range_wrap = RangeWrapper(right_user.mls_range)
                right_level = right_user.mls_level
                right_range = right_user.mls_range
            except MLSDisabled:
                right_level_wrap = None
                right_range_wrap = None
                right_level = "None (MLS Disabled)"
                right_range = "None (MLS Disabled)"

            if left_level_wrap != right_level_wrap:
                added_level = right_level
                removed_level = left_level
            else:
                added_level = None
                removed_level = None

            if left_range_wrap != right_range_wrap:
                added_range = right_range
                removed_range = left_range
            else:
                added_range = None
                removed_range = None

            if added_roles or removed_roles or removed_level or removed_range:
                self.modified_users.append(ModifiedUser(left_user,
                                                        added_roles,
                                                        removed_roles,
                                                        matched_roles,
                                                        added_level,
                                                        removed_level,
                                                        added_range,
                                                        removed_range))

    added_users = DiffResultDescriptor[User](diff_users)
    removed_users = DiffResultDescriptor[User](diff_users)
    modified_users = DiffResultDescriptor[ModifiedUser](diff_users)

    #
    # Internal functions
    #
    def _reset_diff(self) -> None:
        """Reset diff results on policy changes."""
        self.log.debug("Resetting user differences")
        del self.added_users
        del self.removed_users
        del self.modified_users
