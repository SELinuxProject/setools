# Copyright 2014-2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from collections.abc import Iterable

from . import policyrep, util
from .descriptors import CriteriaSetDescriptor
from .mixins import MatchName
from .query import PolicyQuery


class TypeAttributeQuery(MatchName, PolicyQuery):

    """
    Query SELinux policy type attributes.

    Parameter:
    policy            The policy to query.

    Keyword Parameters/Class attributes:
    name                The type name to match.
    name_regex          If true, regular expression matching
                        will be used on the type names.
    types               The type to match.
    types_equal         If true, only attributes with type sets
                        that are equal to the criteria will
                        match.  Otherwise, any intersection
                        will match.
    types_regex         If true, regular expression matching
                        will be used on the type names instead
                        of set logic.
    """

    types = CriteriaSetDescriptor[policyrep.Type]("types_regex", "lookup_type")
    types_equal: bool = False
    types_regex: bool = False

    def results(self) -> Iterable[policyrep.TypeAttribute]:
        """Generator which yields all matching types."""
        self.log.info(f"Generating type attribute results from {self.policy}")
        self._match_name_debug(self.log)
        self.log.debug(f"{self.types=}, {self.types_regex=}, {self.types_equal=}")

        for attr in self.policy.typeattributes():
            if not self._match_name(attr):
                continue

            if self.types and not util.match_regex_or_set(
                    set(attr.expand()),
                    self.types,
                    self.types_equal,
                    self.types_regex):
                continue

            yield attr
