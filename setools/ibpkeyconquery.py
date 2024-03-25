# Copyright 2018, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from ipaddress import IPv6Address
from collections.abc import Iterable
import typing

from . import mixins, policyrep, query, util

__all__: typing.Final[tuple[str, ...]] = ("IbpkeyconQuery",)


class IbpkeyconQuery(mixins.MatchContext, query.PolicyQuery):

    """
    Infiniband pkey context query.

    Parameter:
    policy          The policy to query.

    Keyword Parameters/Class attributes:
    subnet_prefix   A subnet prefix to match.
    pkeys           A 2-tuple of the pkey range to match. (Set both to
                    the same value for a single pkey)
    pkeys_subset    If true, the criteria will match if it is a subset
                    of the ibpkeycon's range.
    pkeys_overlap   If true, the criteria will match if it overlaps
                    any of the ibpkeycon's range.
    pkeys_superset  If true, the criteria will match if it is a superset
                    of the ibpkeycon's range.
    pkeys_proper    If true, use proper superset/subset operations.
                    No effect if not using set operations.
    user            The criteria to match the context's user.
    user_regex      If true, regular expression matching
                    will be used on the user.
    role            The criteria to match the context's role.
    role_regex      If true, regular expression matching
                    will be used on the role.
    type_           The criteria to match the context's type.
    type_regex      If true, regular expression matching
                    will be used on the type.
    range_          The criteria to match the context's range.
    range_subset    If true, the criteria will match if it is a subset
                    of the context's range.
    range_overlap   If true, the criteria will match if it overlaps
                    any of the context's range.
    range_superset  If true, the criteria will match if it is a superset
                    of the context's range.
    range_proper    If true, use proper superset/subset operations.
                    No effect if not using set operations.
    """

    _subnet_prefix: IPv6Address | None = None
    _pkeys: policyrep.IbpkeyconRange | None = None
    pkeys_subset: bool = False
    pkeys_overlap: bool = False
    pkeys_superset: bool = False
    pkeys_proper: bool = False

    @property
    def pkeys(self) -> policyrep.IbpkeyconRange | None:
        return self._pkeys

    @pkeys.setter
    def pkeys(self, value: tuple[int, int] | None) -> None:
        if value:
            self._pkeys = policyrep.IbpkeyconRange(*value)
        else:
            self._pkeys = None

    @property
    def subnet_prefix(self) -> IPv6Address | None:
        return self._subnet_prefix

    @subnet_prefix.setter
    def subnet_prefix(self, value: str | IPv6Address | None) -> None:
        if value:
            self._subnet_prefix = IPv6Address(value)
        else:
            self._subnet_prefix = None

    def results(self) -> Iterable[policyrep.Ibpkeycon]:
        """Generator which yields all matching ibpkeycons."""
        self.log.info(f"Generating ibpkeycon results from {self.policy}")
        self.log.debug(f"{self.subnet_prefix=}")
        self.log.debug(f"{self.pkeys=}, {self.pkeys_overlap=}, {self.pkeys_subset=}, "
                       f"{self.pkeys_superset=}, {self.pkeys_proper=}")
        self._match_context_debug(self.log)

        for pk in self.policy.ibpkeycons():
            if self.subnet_prefix is not None and self.subnet_prefix != pk.subnet_prefix:
                continue

            if self.pkeys and not util.match_range(
                    pk.pkeys,
                    self.pkeys,
                    self.pkeys_subset,
                    self.pkeys_overlap,
                    self.pkeys_superset,
                    self.pkeys_proper):
                continue

            if not self._match_context(pk.context):
                continue

            yield pk
