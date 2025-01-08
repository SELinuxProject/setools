# Copyright 2025, Christian Göttsche
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from collections.abc import Iterable
import typing

from . import mixins, policyrep, query

__all__: typing.Final[tuple[str, ...]] = ("RoleTypesQuery",)


class RoleTypesQuery(mixins.MatchName, query.PolicyQuery):

    """
    Query SELinux policy roles.

    Parameter:
    policy            The policy to query.

    Keyword Parameters/Class attributes:
    name         The type name to match.
    name_regex   If true, regular expression matching
                 will be used on the type names.
    """

    def results(self) -> Iterable[policyrep.Role]:
        """Generator which yields all matching roles."""
        self.log.info(f"Generating role-types results from {self.policy}")
        self._match_name_debug(self.log)

        for r in self.policy.roles():
            for t in r.types():
                if self._match_name(t):
                    yield r
                    break
