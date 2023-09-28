# Copyright 2014-2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from typing import cast, Iterable

from .query import PolicyQuery
from .descriptors import CriteriaDescriptor, CriteriaSetDescriptor
from .mixins import MatchObjClass
from .policyrep import AnyDefault, DefaultRange, DefaultRuletype, DefaultValue, DefaultRangeValue


class DefaultQuery(MatchObjClass, PolicyQuery):

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

    ruletype = CriteriaSetDescriptor(enum_class=DefaultRuletype)
    default = CriteriaDescriptor(enum_class=DefaultValue)
    default_range = CriteriaDescriptor(enum_class=DefaultRangeValue)

    def results(self) -> Iterable[AnyDefault]:
        """Generator which yields all matching default_* statements."""
        self.log.info("Generating default_* results from {0.policy}".format(self))
        self.log.debug("Ruletypes: {0.ruletype!r}".format(self))
        self._match_object_class_debug(self.log)
        self.log.debug("Default: {0.default!r}".format(self))
        self.log.debug("Range: {0.default_range!r}".format(self))

        for d in self.policy.defaults():
            if self.ruletype and d.ruletype not in self.ruletype:
                continue

            if not self._match_object_class(d):
                continue

            if self.default and d.default != self.default:
                continue

            if self.default_range:
                try:
                    if cast(DefaultRange, d).default_range != self.default_range:
                        continue
                except AttributeError:
                    continue

            yield d
