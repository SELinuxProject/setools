# Copyright 2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
import logging
from typing import Iterable

from .mixins import MatchAlias, MatchName
from .policyrep import Category
from .query import PolicyQuery


class CategoryQuery(MatchAlias, MatchName, PolicyQuery):

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

    def __init__(self, policy, **kwargs) -> None:
        super(CategoryQuery, self).__init__(policy, **kwargs)
        self.log = logging.getLogger(__name__)

    def results(self) -> Iterable[Category]:
        """Generator which yields all matching categories."""
        self.log.info("Generating category results from {0.policy}".format(self))
        self._match_name_debug(self.log)
        self._match_alias_debug(self.log)

        for cat in self.policy.categories():
            if not self._match_name(cat):
                continue

            if not self._match_alias(cat):
                continue

            yield cat
