# Copyright 2014-2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from collections.abc import Iterable

from . import mixins, policyrep, query, util
from .descriptors import CriteriaSetDescriptor


class TypeQuery(mixins.MatchAlias, mixins.MatchName, query.PolicyQuery):

    """
    Query SELinux policy types.

    Parameter:
    policy              The policy to query.

    Keyword Parameters/Class attributes:
    name                The type name to match.
    name_regex          If true, regular expression matching
                        will be used on the type names.
    alias               The alias name to match.
    alias_regex         If true, regular expression matching
                        will be used on the alias names.
    attrs               The attribute to match.
    attrs_equal         If true, only types with attribute sets
                        that are equal to the criteria will
                        match.  Otherwise, any intersection
                        will match.
    attrs_regex         If true, regular expression matching
                        will be used on the attribute names instead
                        of set logic.
    permissive          The permissive state to match.  If this
                        is None, the state is not matched.
    """

    attrs = CriteriaSetDescriptor[policyrep.TypeAttribute]("attrs_regex", "lookup_typeattr")
    attrs_regex: bool = False
    attrs_equal: bool = False
    _permissive: bool | None = None

    @property
    def permissive(self) -> bool | None:
        return self._permissive

    @permissive.setter
    def permissive(self, value) -> None:
        if value is None:
            self._permissive = None
        else:
            self._permissive = bool(value)

    def results(self) -> Iterable[policyrep.Type]:
        """Generator which yields all matching types."""
        self.log.info(f"Generating type results from {self.policy}")
        self._match_name_debug(self.log)
        self._match_alias_debug(self.log)
        self.log.debug(f"{self.attrs=}, {self.attrs_regex=}, {self.attrs_equal=}")
        self.log.debug(f"{self.permissive=}")

        for t in self.policy.types():
            if not self._match_name(t):
                continue

            if not self._match_alias(t):
                continue

            if self.attrs and not util.match_regex_or_set(
                    set(t.attributes()),
                    self.attrs,
                    self.attrs_equal,
                    self.attrs_regex):
                continue

            if self.permissive is not None and t.ispermissive != self.permissive:
                continue

            yield t
