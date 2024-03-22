# Copyright 2014-2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from collections.abc import Iterable
import typing

from . import mixins, policyrep, query, util
from .descriptors import CriteriaDescriptor, CriteriaSetDescriptor

__all__: typing.Final[tuple[str, ...]] = ("MLSRuleQuery",)


class MLSRuleQuery(mixins.MatchObjClass, query.PolicyQuery):

    """
    Query MLS rules.

    Parameter:
    policy            The policy to query.

    Keyword Parameters/Class attributes:
    ruletype         The list of rule type(s) to match.
    source           The name of the source type/attribute to match.
    source_regex     If true, regular expression matching will
                     be used on the source type/attribute.
    target           The name of the target type/attribute to match.
    target_regex     If true, regular expression matching will
                     be used on the target type/attribute.
    tclass           The object class(es) to match.
    tclass_regex     If true, use a regular expression for
                     matching the rule's object class.
    """

    ruletype = CriteriaSetDescriptor[policyrep.MLSRuletype](enum_class=policyrep.MLSRuletype)
    source = CriteriaDescriptor[policyrep.TypeOrAttr]("source_regex", "lookup_type_or_attr")
    source_regex: bool = False
    source_indirect: bool = True
    target = CriteriaDescriptor[policyrep.TypeOrAttr]("target_regex", "lookup_type_or_attr")
    target_regex: bool = False
    target_indirect: bool = True
    tclass = CriteriaSetDescriptor[policyrep.ObjClass]("tclass_regex", "lookup_class")
    tclass_regex: bool = False
    default = CriteriaDescriptor[policyrep.Range](lookup_function="lookup_range")
    default_overlap: bool = False
    default_subset: bool = False
    default_superset: bool = False
    default_proper: bool = False

    def results(self) -> Iterable[policyrep.MLSRule]:
        """Generator which yields all matching MLS rules."""
        self.log.info(f"Generating MLS rule results from {self.policy}")
        self.log.debug(f"{self.ruletype=}")
        self.log.debug(f"{self.source=}, {self.source_indirect=}, {self.source_regex=}")
        self.log.debug(f"{self.target=}, {self.target_indirect=}, {self.target_regex=}")
        self._match_object_class_debug(self.log)
        self.log.debug(f"{self.default=}, {self.default_overlap=}, {self.default_subset=}, "
                       f"{self.default_superset=}, {self.default_proper=}")

        for rule in self.policy.mlsrules():
            #
            # Matching on rule type
            #
            if self.ruletype:
                if rule.ruletype not in self.ruletype:
                    continue

            #
            # Matching on source type
            #
            if self.source and not util.match_indirect_regex(
                    rule.source,
                    self.source,
                    self.source_indirect,
                    self.source_regex):
                continue

            #
            # Matching on target type
            #
            if self.target and not util.match_indirect_regex(
                    rule.target,
                    self.target,
                    self.target_indirect,
                    self.target_regex):
                continue

            #
            # Matching on object class
            #
            if not self._match_object_class(rule):
                continue

            #
            # Matching on range
            #
            if self.default and not util.match_range(
                    rule.default,
                    self.default,
                    self.default_subset,
                    self.default_overlap,
                    self.default_superset,
                    self.default_proper):
                continue

            # if we get here, we have matched all available criteria
            yield rule
