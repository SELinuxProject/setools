# Copyright 2014, Tresys Technology, LLC
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
import re

from .policyrep.rule import InvalidRuleUse, RuleNotConditional
from . import rulequery


class TERuleQuery(rulequery.RuleQuery):

    """Query the Type Enforcement rules."""

    def __init__(self, policy,
                 ruletype=[],
                 source="", source_regex=False, source_indirect=True,
                 target="", target_regex=False, target_indirect=True,
                 tclass="", tclass_regex=False,
                 perms=set(), perms_equal=False,
                 default="", default_regex=False,
                 boolean=set(), boolean_regex=False, boolean_equal=False):
        """
        Parameter:
        policy            The policy to query.
        ruletype	      The rule type(s) to match.
        source		      The name of the source type/attribute to match.
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

        for r in self.policy.terules():
            #
            # Matching on rule type
            #
            if self.ruletype:
                if r.ruletype not in self.ruletype:
                    continue

            #
            # Matching on source type
            #
            if self.source and not self._match_indirect_regex(
                    r.source,
                    self.source,
                    self.source_indirect,
                    self.source_regex,
                    self.source_cmp):
                continue

            #
            # Matching on target type
            #
            if self.target and not self._match_indirect_regex(
                    r.target,
                    self.target,
                    self.target_indirect,
                    self.target_regex,
                    self.target_cmp):
                continue

            #
            # Matching on object class
            #
            if self.tclass and not self._match_object_class(
                    r.tclass,
                    self.tclass_cmp,
                    self.tclass_regex):
                continue

            #
            # Matching on permission set
            #
            if self.perms:
                try:
                    if not self._match_set(
                            r.perms,
                            self.perms,
                            self.perms_equal):
                        continue
                except InvalidRuleUse:
                    continue

            #
            # Matching on default type
            #
            if self.default:
                try:
                    if not self._match_regex(
                            r.default,
                            self.default,
                            self.default_regex,
                            self.default_cmp):
                        continue
                except InvalidRuleUse:
                    continue

            #
            # Match on Boolean in conditional expression
            #
            if self.boolean:
                try:
                    if not self._match_regex_or_set(
                            set(str(b) for b in r.conditional.booleans),
                            self.boolean,
                            self.boolean_equal,
                            self.boolean_regex,
                            self.boolean_cmp):
                        continue
                except RuleNotConditional:
                    continue

            # if we get here, we have matched all available criteria
            yield r

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

        if self.boolean_regex:
            self.boolean_cmp = re.compile(self.boolean)
        else:
            self.boolean_cmp = None

    def set_perms(self, perms, **opts):
        """
        Set the permission set for the TE rule query.

        Parameter:
        perms       The permissions to match.

        Options:
        equal       If true, the permission set of the rule
                    must equal the permissions criteria to
                    match. If false, permission in the critera
                    will cause a rule match.

        Exceptions:
        NameError   Invalid permission set keyword option.
        """

        if isinstance(perms, str):
            self.perms = perms
        else:
            self.perms = set(perms)

        for k in list(opts.keys()):
            if k == "equal":
                self.perms_equal = opts[k]
            else:
                raise NameError("Invalid permission set option: {0}".format(k))
