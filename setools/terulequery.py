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
import re

from . import mixins, query
from .descriptors import CriteriaDescriptor, CriteriaSetDescriptor, RuletypeDescriptor
from .policyrep.exception import RuleUseError, RuleNotConditional


class TERuleQuery(mixins.MatchObjClass, mixins.MatchPermission, query.PolicyQuery):

    """
    Query the Type Enforcement rules.

    Parameter:
    policy            The policy to query.

    Keyword Parameters/Class attributes:
    ruletype          The list of rule type(s) to match.
    source            The name of the source type/attribute to match.
    source_indirect   If true, members of an attribute will be
                      matched rather than the attribute itself.
                      Default is true.
    source_regex      If true, regular expression matching will
                      be used on the source type/attribute.
                      Obeys the source_indirect option.
                      Default is false.
    target            The name of the target type/attribute to match.
    target_indirect   If true, members of an attribute will be
                      matched rather than the attribute itself.
                      Default is true.
    target_regex      If true, regular expression matching will
                      be used on the target type/attribute.
                      Obeys target_indirect option.
                      Default is false.
    tclass            The object class(es) to match.
    tclass_regex      If true, use a regular expression for
                      matching the rule's object class.
                      Default is false.
    perms             The set of permission(s) to match.
    perms_equal       If true, the permission set of the rule
                      must exactly match the permissions
                      criteria.  If false, any set intersection
                      will match.
                      Default is false.
    perms_regex       If true, regular expression matching will be used
                      on the permission names instead of set logic.
    default           The name of the default type to match.
    default_regex     If true, regular expression matching will be
                      used on the default type.
                      Default is false.
    boolean           The set of boolean(s) to match.
    boolean_regex     If true, regular expression matching will be
                      used on the booleans.
                      Default is false.
    boolean_equal     If true, the booleans in the conditional
                      expression of the rule must exactly match the
                      criteria.  If false, any set intersection
                      will match.  Default is false.
    """

    ruletype = RuletypeDescriptor("validate_te_ruletype")
    source = CriteriaDescriptor("source_regex", "lookup_type_or_attr")
    source_regex = False
    source_indirect = True
    target = CriteriaDescriptor("target_regex", "lookup_type_or_attr")
    target_regex = False
    target_indirect = True
    default = CriteriaDescriptor("default_regex", "lookup_type")
    default_regex = False
    boolean = CriteriaSetDescriptor("boolean_regex", "lookup_boolean")
    boolean_regex = False
    boolean_equal = False

    def results(self):
        """Generator which yields all matching TE rules."""
        self.log.info("Generating results from {0.policy}".format(self))
        self.log.debug("Ruletypes: {0.ruletype}".format(self))
        self.log.debug("Source: {0.source!r}, indirect: {0.source_indirect}, "
                       "regex: {0.source_regex}".format(self))
        self.log.debug("Target: {0.target!r}, indirect: {0.target_indirect}, "
                       "regex: {0.target_regex}".format(self))
        self.log.debug("Class: {0.tclass!r}, regex: {0.tclass_regex}".format(self))
        self.log.debug("Perms: {0.perms!r}, regex: {0.perms_regex}, eq: {0.perms_equal}".
                       format(self))
        self.log.debug("Default: {0.default!r}, regex: {0.default_regex}".format(self))
        self.log.debug("Boolean: {0.boolean!r}, eq: {0.boolean_equal}, "
                       "regex: {0.boolean_regex}".format(self))

        for rule in self.policy.terules():
            #
            # Matching on rule type
            #
            if self.ruletype:
                if rule.ruletype not in self.ruletype:
                    continue

            #
            # Matching on source type
            #
            if self.source and not self._match_indirect_regex(
                    rule.source,
                    self.source,
                    self.source_indirect,
                    self.source_regex):
                continue

            #
            # Matching on target type
            #
            if self.target and not self._match_indirect_regex(
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
            # Matching on permission set
            #
            try:
                if not self._match_perms(rule):
                    continue
            except RuleUseError:
                continue

            #
            # Matching on default type
            #
            if self.default:
                try:
                    if not self._match_regex(
                            rule.default,
                            self.default,
                            self.default_regex):
                        continue
                except RuleUseError:
                    continue

            #
            # Match on Boolean in conditional expression
            #
            if self.boolean:
                try:
                    if not self._match_regex_or_set(
                            rule.conditional.booleans,
                            self.boolean,
                            self.boolean_equal,
                            self.boolean_regex):
                        continue
                except RuleNotConditional:
                    continue

            # if we get here, we have matched all available criteria
            yield rule
