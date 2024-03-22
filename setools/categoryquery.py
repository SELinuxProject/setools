# Copyright 2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from collections.abc import Iterable
import typing

from . import mixins, policyrep, query

__all__: typing.Final[tuple[str, ...]] = ("CategoryQuery",)


class CategoryQuery(mixins.MatchAlias, mixins.MatchName, query.PolicyQuery):

    """
    Query MLS Categories

    Parameter:
    policy       The policy to query.

    Keyword Parameters/Class attributes:
    name         The name of the category to match.
    name_regex   If true, regular expression matching will
                 be used for matching the name.
    alias        The alias name to match.
    alias_regex  If true, regular expression matching
                 will be used on the alias names.
    """

    def results(self) -> Iterable[policyrep.Category]:
        """Generator which yields all matching categories."""
        self.log.info(f"Generating category results from {self.policy}")
        self._match_name_debug(self.log)
        self._match_alias_debug(self.log)

        for cat in self.policy.categories():
            if not self._match_name(cat):
                continue

            if not self._match_alias(cat):
                continue

            yield cat
