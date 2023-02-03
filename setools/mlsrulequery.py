# Copyright 2014-2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
import logging
from typing import Iterable

from .descriptors import CriteriaDescriptor, CriteriaSetDescriptor
from .mixins import MatchObjClass
from .policyrep import MLSRule, MLSRuletype
from .query import PolicyQuery
from .util import match_indirect_regex, match_range


class MLSRuleQuery(MatchObjClass, PolicyQuery):

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

    ruletype = CriteriaSetDescriptor(enum_class=MLSRuletype)
    source = CriteriaDescriptor("source_regex", "lookup_type_or_attr")
    source_regex: bool = False
    source_indirect: bool = True
    target = CriteriaDescriptor("target_regex", "lookup_type_or_attr")
    target_regex: bool = False
    target_indirect: bool = True
    tclass = CriteriaSetDescriptor("tclass_regex", "lookup_class")
    tclass_regex: bool = False
    default = CriteriaDescriptor(lookup_function="lookup_range")
    default_overlap: bool = False
    default_subset: bool = False
    default_superset: bool = False
    default_proper: bool = False

    def __init__(self, policy, **kwargs) -> None:
        super(MLSRuleQuery, self).__init__(policy, **kwargs)
        self.log = logging.getLogger(__name__)

    def results(self) -> Iterable[MLSRule]:
        """Generator which yields all matching MLS rules."""
        self.log.info("Generating MLS rule results from {0.policy}".format(self))
        self.log.debug("Ruletypes: {0.ruletype}".format(self))
        self.log.debug("Source: {0.source!r}, indirect: {0.source_indirect}, "
                       "regex: {0.source_regex}".format(self))
        self.log.debug("Target: {0.target!r}, indirect: {0.target_indirect}, "
                       "regex: {0.target_regex}".format(self))
        self._match_object_class_debug(self.log)
        self.log.debug("Default: {0.default!r}, overlap: {0.default_overlap}, "
                       "subset: {0.default_subset}, superset: {0.default_superset}, "
                       "proper: {0.default_proper}".format(self))

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
            if self.source and not match_indirect_regex(
                    rule.source,
                    self.source,
                    self.source_indirect,
                    self.source_regex):
                continue

            #
            # Matching on target type
            #
            if self.target and not match_indirect_regex(
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
            if self.default and not match_range(
                    rule.default,
                    self.default,
                    self.default_subset,
                    self.default_overlap,
                    self.default_superset,
                    self.default_proper):
                continue

            # if we get here, we have matched all available criteria
            yield rule
