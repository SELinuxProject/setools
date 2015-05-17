# Copyright 2014-2015, Tresys Technology, LLC
#
# This file is part of SETools.
#
# SETools is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation, either version 2.1 of
# the License, or (at your option) any later version.
#
# SETools is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with SETools.  If not, see
# <http://www.gnu.org/licenses/>.
#
import logging

from . import mixins, query
from .descriptors import CriteriaDescriptor, CriteriaSetDescriptor, RuletypeDescriptor


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

    ruletype = RuletypeDescriptor("validate_mls_ruletype")
    source = CriteriaDescriptor("source_regex", "lookup_type_or_attr")
    source_regex = False
    target = CriteriaDescriptor("target_regex", "lookup_type_or_attr")
    target_regex = False
    tclass = CriteriaSetDescriptor("tclass_regex", "lookup_class")
    tclass_regex = False
    default = CriteriaDescriptor(lookup_function="lookup_range")
    default_overlap = False
    default_subset = False
    default_superset = False
    default_proper = False

    def results(self):
        """Generator which yields all matching MLS rules."""
        self.log.info("Generating results from {0.policy}".format(self))
        self.log.debug("Ruletypes: {0.ruletype}".format(self))
        self.log.debug("Source: {0.source!r}, regex: {0.source_regex}".format(self))
        self.log.debug("Target: {0.target!r}, regex: {0.target_regex}".format(self))
        self.log.debug("Class: {0.tclass!r}, regex: {0.tclass_regex}".format(self))
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
            if self.source and not self._match_regex(
                    rule.source,
                    self.source,
                    self.source_regex):
                continue

            #
            # Matching on target type
            #
            if self.target and not self._match_regex(
                    rule.target,
                    self.target,
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
            if self.default and not self._match_range(
                    rule.default,
                    self.default,
                    self.default_subset,
                    self.default_overlap,
                    self.default_superset,
                    self.default_proper):
                continue

            # if we get here, we have matched all available criteria
            yield rule
