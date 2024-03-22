# Copyright 2014-2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from collections.abc import Iterable
import typing

from . import mixins, policyrep, query, util
from .descriptors import CriteriaSetDescriptor

__all__: typing.Final[tuple[str, ...]] = ("RoleQuery",)


class RoleQuery(mixins.MatchName, query.PolicyQuery):

    """
    Query SELinux policy roles.

    Parameter:
    policy            The policy to query.

    Keyword Parameters/Class attributes:
    name         The role name to match.
    name_regex   If true, regular expression matching
                 will be used on the role names.
    types        The type to match.
    types_equal  If true, only roles with type sets
                 that are equal to the criteria will
                 match.  Otherwise, any intersection
                 will match.
    types_regex  If true, regular expression matching
                 will be used on the type names instead
                 of set logic.
    """

    types = CriteriaSetDescriptor[policyrep.Type]("types_regex", "lookup_type")
    types_equal: bool = False
    types_regex: bool = False

    def results(self) -> Iterable[policyrep.Role]:
        """Generator which yields all matching roles."""
        self.log.info(f"Generating role results from {self.policy}")
        self._match_name_debug(self.log)
        self.log.debug(f"{self.types=}, {self.types_regex=}, {self.types_equal=}")

        for r in self.policy.roles():
            if not self._match_name(r):
                continue

            if self.types and not util.match_regex_or_set(
                    set(r.types()),
                    self.types,
                    self.types_equal,
                    self.types_regex):
                continue

            yield r
