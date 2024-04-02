# Copyright 2014-2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from collections.abc import Iterable
import typing

from . import mixins, policyrep, query

__all__: typing.Final[tuple[str, ...]] = ("BoolQuery",)


class BoolQuery(mixins.MatchName, query.PolicyQuery):

    """Query SELinux policy Booleans.

    Parameter:
    policy          The policy to query.

    Keyword Parameters/Class attributes:
    name            The Boolean name to match.
    name_regex      If true, regular expression matching
                    will be used on the Boolean name.
    default         The default state to match.  If this
                    is None, the default state not be matched.
    """

    _default: bool | None = None

    @property
    def default(self) -> bool | None:
        return self._default

    @default.setter
    def default(self, value) -> None:
        if value is None:
            self._default = None
        else:
            self._default = bool(value)

    def results(self) -> Iterable[policyrep.Boolean]:
        """Generator which yields all Booleans matching the criteria."""
        self.log.info(f"Generating Boolean results from {self.policy}")
        self._match_name_debug(self.log)
        self.log.debug(f"{self.default=}")

        for boolean in self.policy.bools():
            if not self._match_name(boolean):
                continue

            if self.default is not None and boolean.state != self.default:
                continue

            yield boolean
