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

from .policyrep.exception import RuleUseError, RuleNotConditional
from . import mixins
from . import rulequery


class TERuleQuery(mixins.MatchPermission, rulequery.RuleQuery):

    """Query the Type Enforcement rules."""

    def __init__(self, policy,
                 ruletype=None,
                 source=None, source_regex=False, source_indirect=True,
                 target=None, target_regex=False, target_indirect=True,
                 tclass=None, tclass_regex=False,
                 perms=None, perms_equal=False,
                 default=None, default_regex=False,
                 boolean=None, boolean_regex=False, boolean_equal=False):
        """
        Parameter:
        policy            The policy to query.
        ruletype          The rule type(s) to match.
        source            The name of the source type/attribute to match.
        source_indirect   If true, members of an attribute will be
                          matched rather than the attribute itself.
        source_regex      If true, regular expression matching will
                          be used on the source type/attribute.
                          Obeys the source_indirect option.
        target            The name of the target type/attribute to match.
        target_indirect   If true, members of an attribute will be
                          matched rather than the attribute itself.
        target_regex      If true, regular expression matching will
                          be used on the target type/attribute.
                          Obeys target_indirect option.
        tclass            The object class(es) to match.
        tclass_regex      If true, use a regular expression for
                          matching the rule's object class.
        perms             The permission(s) to match.
        perms_equal       If true, the permission set of the rule
                          must exactly match the permissions
                          criteria.  If false, any set intersection
                          will match.
        default           The name of the default type to match.
        default_regex     If true, regular expression matching will be
                          used on the default type.
        """
        self.log = logging.getLogger(self.__class__.__name__)

        self.policy = policy

        self.set_ruletype(ruletype)
        self.set_source(source, indirect=source_indirect, regex=source_regex)
        self.set_target(target, indirect=target_indirect, regex=target_regex)
        self.set_tclass(tclass, regex=tclass_regex)
        self.set_perms(perms, equal=perms_equal)
        self.set_default(default, regex=default_regex)
        self.set_boolean(boolean, regex=boolean_regex, equal=boolean_equal)

    def results(self):
        """Generator which yields all matching TE rules."""
        self.log.info("Generating results from {0.policy}".format(self))
        self.log.debug("Ruletypes: {0.ruletype}".format(self))
        self.log.debug("Source: {0.source_cmp!r}, indirect: {0.source_indirect}, "
                       "regex: {0.source_regex}".format(self))
        self.log.debug("Target: {0.target_cmp!r}, indirect: {0.target_indirect}, "
                       "regex: {0.target_regex}".format(self))
        self.log.debug("Class: {0.tclass_cmp!r}, regex: {0.tclass_regex}".format(self))
        self.log.debug("Perms: {0.perms_cmp}, eq: {0.perms_equal}".format(self))
        self.log.debug("Default: {0.default_cmp!r}, regex: {0.default_regex}".format(self))
        self.log.debug("Boolean: {0.boolean_cmp!r}, eq: {0.boolean_equal}, "
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
                    self.source_cmp,
                    self.source_indirect,
                    self.source_regex):
                continue

            #
            # Matching on target type
            #
            if self.target and not self._match_indirect_regex(
                    rule.target,
                    self.target_cmp,
                    self.target_indirect,
                    self.target_regex):
                continue

            #
            # Matching on object class
            #
            if self.tclass and not self._match_object_class(rule.tclass):
                continue

            #
            # Matching on permission set
            #
            if self.perms:
                try:
                    if not self._match_perms(rule.perms):
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
                            self.default_cmp,
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
                            self.boolean_cmp,
                            self.boolean_equal,
                            self.boolean_regex):
                        continue
                except RuleNotConditional:
                    continue

            # if we get here, we have matched all available criteria
            yield rule

    def set_boolean(self, boolean, **opts):
        """
        Set the Boolean for the TE rule query.

        Parameter:
        boolean     The Boolean names to match in the TE rule
                    conditional expression.

        Options:
        regex       If true, regular expression matching will be used.

        Exceptions:
        NameError   Invalid permission set keyword option.
        """

        self.boolean = boolean

        for k in list(opts.keys()):
            if k == "regex":
                self.boolean_regex = opts[k]
            elif k == "equal":
                self.boolean_equal = opts[k]
            else:
                raise NameError("Invalid permission set option: {0}".format(k))

        if not self.boolean:
            self.boolean_cmp = None
        elif self.boolean_regex:
            self.boolean_cmp = re.compile(self.boolean)
        else:
            self.boolean_cmp = set(self.policy.lookup_boolean(b) for b in self.boolean)

    def set_ruletype(self, ruletype):
        """
        Set the rule types for the rule query.

        Parameter:
        ruletype    The rule types to match.
        """
        if ruletype:
            self.policy.validate_te_ruletype(ruletype)

        self.ruletype = ruletype

    def set_default(self, default, **opts):
        """
        Set the criteria for the rule's default type.

        Parameter:
        default     Name to match the rule's default type.

        Keyword Options:
        regex       If true, regular expression matching will be used.

        Exceptions:
        NameError   Invalid keyword option.
        """

        self.default = default

        for k in list(opts.keys()):
            if k == "regex":
                self.default_regex = opts[k]
            else:
                raise NameError("Invalid default option: {0}".format(k))

        if not self.default:
            self.default_cmp = None
        elif self.default_regex:
            self.default_cmp = re.compile(self.default)
        else:
            self.default_cmp = self.policy.lookup_type(self.default)
