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

from .policyrep.exception import InvalidType, RuleUseError

from . import rulequery


class RBACRuleQuery(rulequery.RuleQuery):

    """Query the RBAC rules."""

    def __init__(self, policy,
                 ruletype=None,
                 source=None, source_regex=False, source_indirect=True,
                 target=None, target_regex=False, target_indirect=True,
                 tclass=None, tclass_regex=False,
                 default=None, default_regex=False):
        """
        Parameters:
        policy          The policy to query.
        ruletype        The rule type(s) to match.
        source          The name of the source role/attribute to match.
        source_indirect If true, members of an attribute will be
                        matched rather than the attribute itself.
        source_regex    If true, regular expression matching will
                        be used on the source role/attribute.
                        Obeys the source_indirect option.
        target          The name of the target role/attribute to match.
        target_indirect If true, members of an attribute will be
                        matched rather than the attribute itself.
        target_regex    If true, regular expression matching will
                        be used on the target role/attribute.
                        Obeys target_indirect option.
        tclass          The object class(es) to match.
        tclass_regex    If true, use a regular expression for
                        matching the rule's object class.
        default         The name of the default role to match.
        default_regex   If true, regular expression matching will
                        be used on the default role.
        """
        self.log = logging.getLogger(self.__class__.__name__)

        self.policy = policy

        self.set_ruletype(ruletype)
        self.set_source(source, indirect=source_indirect, regex=source_regex)
        self.set_target(target, indirect=target_indirect, regex=target_regex)
        self.set_tclass(tclass, regex=tclass_regex)
        self.set_default(default, regex=default_regex)

    def results(self):
        """Generator which yields all matching RBAC rules."""
        self.log.info("Generating results from {0.policy}".format(self))
        self.log.debug("Ruletypes: {0.ruletype}".format(self))
        self.log.debug("Source: {0.source_cmp!r}, indirect: {0.source_indirect}, "
                       "regex: {0.source_regex}".format(self))
        self.log.debug("Target: {0.target_cmp!r}, indirect: {0.target_indirect}, "
                       "regex: {0.target_regex}".format(self))
        self.log.debug("Class: {0.tclass_cmp!r}, regex: {0.tclass_regex}".format(self))
        self.log.debug("Default: {0.default_cmp!r}, regex: {0.default_regex}".format(self))

        for rule in self.policy.rbacrules():
            #
            # Matching on rule type
            #
            if self.ruletype:
                if rule.ruletype not in self.ruletype:
                    continue

            #
            # Matching on source role
            #
            if self.source and not self._match_indirect_regex(
                    rule.source,
                    self.source_cmp,
                    self.source_indirect,
                    self.source_regex):
                continue

            #
            # Matching on target type (role_transition)/role(allow)
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
            if self.tclass:
                try:
                    if not self._match_object_class(rule.tclass):
                        continue
                except RuleUseError:
                    continue

            #
            # Matching on default role
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

            # if we get here, we have matched all available criteria
            yield rule

    def set_ruletype(self, ruletype):
        """
        Set the rule types for the rule query.

        Parameter:
        ruletype    The rule types to match.
        """
        if ruletype:
            self.policy.validate_rbac_ruletype(ruletype)

        self.ruletype = ruletype

    def set_source(self, source, **opts):
        """
        Set the criteria for the rule's source.

        Parameter:
        source      Name to match the rule's source.

        Keyword Options:
        indirect    If true, members of an attribute will be
                    matched rather than the attribute itself.
        regex       If true, regular expression matching will
                    be used.  Obeys the indirect option.

        Exceptions:
        NameError   Invalid keyword option.
        """

        self.source = source

        for k in list(opts.keys()):
            if k == "indirect":
                self.source_indirect = opts[k]
            elif k == "regex":
                self.source_regex = opts[k]
            else:
                raise NameError("Invalid source option: {0}".format(k))

        if not self.source:
            self.source_cmp = None
        elif self.source_regex:
            self.source_cmp = re.compile(self.source)
        else:
            self.source_cmp = self.policy.lookup_role(self.source)

    def set_target(self, target, **opts):
        """
        Set the criteria for the rule's target.

        Parameter:
        target      Name to match the rule's target.

        Keyword Options:
        indirect    If true, members of an attribute will be
                    matched rather than the attribute itself.
        regex       If true, regular expression matching will
                    be used.  Obeys the indirect option.

        Exceptions:
        NameError   Invalid keyword option.
        """

        self.target = target

        for k in list(opts.keys()):
            if k == "indirect":
                self.target_indirect = opts[k]
            elif k == "regex":
                self.target_regex = opts[k]
            else:
                raise NameError("Invalid target option: {0}".format(k))

        if not self.target:
            self.target_cmp = None
        elif self.target_regex:
            self.target_cmp = re.compile(self.target)
        else:
            try:
                self.target_cmp = self.policy.lookup_type_or_attr(self.target)
            except InvalidType:
                self.target_cmp = self.policy.lookup_role(self.target)

    def set_default(self, default, **opts):
        """
        Set the criteria for the rule's default role.

        Parameter:
        default     Name to match the rule's default role.

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
            self.default_cmp = self.policy.lookup_role(self.default)
