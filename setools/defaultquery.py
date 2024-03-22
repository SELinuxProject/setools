# Copyright 2014-2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from collections.abc import Iterable
import typing

from . import mixins, policyrep, query
from .descriptors import CriteriaDescriptor, CriteriaSetDescriptor

__all__: typing.Final[tuple[str, ...]] = ("DefaultQuery",)


class DefaultQuery(mixins.MatchObjClass, query.PolicyQuery):

    """
    Query default_* statements.

    Parameter:
    policy          The policy to query.

    Keyword Parameters/Class attributes:
    ruletype        The rule type(s) to match.
    tclass          The object class(es) to match.
    tclass_regex    If true, use a regular expression for
                    matching the rule's object class.
    default         The default to base new contexts (e.g. "source" or "target")
    default_range   The range to use on new context, default_range only
                    ("low", "high", "low_high")
    """

    ruletype = CriteriaSetDescriptor[policyrep.DefaultRuletype](
        enum_class=policyrep.DefaultRuletype)
    default = CriteriaDescriptor[policyrep.DefaultValue](
        enum_class=policyrep.DefaultValue)
    default_range = CriteriaDescriptor[policyrep.DefaultRangeValue](
        enum_class=policyrep.DefaultRangeValue)

    def results(self) -> Iterable[policyrep.AnyDefault]:
        """Generator which yields all matching default_* statements."""
        self.log.info(f"Generating default_* results from {self.policy}")
        self.log.debug(f"{self.ruletype=}")
        self._match_object_class_debug(self.log)
        self.log.debug(f"{self.default=}")
        self.log.debug(f"{self.default_range=}")

        for d in self.policy.defaults():
            if self.ruletype and d.ruletype not in self.ruletype:
                continue

            if not self._match_object_class(d):
                continue

            if self.default and d.default != self.default:
                continue

            if self.default_range:
                try:
                    if typing.cast(policyrep.DefaultRange, d).default_range != self.default_range:
                        continue
                except AttributeError:
                    continue

            yield d
