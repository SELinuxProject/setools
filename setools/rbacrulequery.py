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
from .policyrep.rule import InvalidRuleUse
from . import rulequery


class RBACRuleQuery(rulequery.RuleQuery):

    """Query the RBAC rules."""

    def __init__(self, policy,
                 ruletype=[],
                 source="", source_regex=False, source_indirect=True,
                 target="", target_regex=False, target_indirect=True,
                 tclass="", tclass_regex=False,
                 default="", default_regex=False):
        """
        Parameters:
        policy          The policy to query.
        ruletype        The rule type(s) to match.
        source	   	    The name of the source role/attribute to match.
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

        self.policy = policy

        self.set_ruletype(ruletype)
        self.set_source(source, indirect=source_indirect, regex=source_regex)
        self.set_target(target, indirect=target_indirect, regex=target_regex)
        self.set_tclass(tclass, regex=tclass_regex)
        self.set_default(default, regex=default_regex)

    def results(self):
        """Generator which yields all matching RBAC rules."""

        for r in self.policy.rbacrules():
            #
            # Matching on rule type
            #
            if self.ruletype:
                if not r.ruletype in self.ruletype:
                    continue

            #
            # Matching on source role
            #
            if self.source and not self._match_indirect_regex(
                    r.source,
                    self.source,
                    self.source_indirect,
                    self.source_regex,
                    self.source_cmp):
                continue

            #
            # Matching on target type (role_transition)/role(allow)
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
            if self.tclass:
                try:
                    if not self._match_object_class(
                            r.tclass,
                            self.tclass,
                            self.tclass_regex,
                            self.tclass_cmp):
                        continue
                except InvalidRuleUse:
                    continue

            #
            # Matching on default role
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

            # if we get here, we have matched all available criteria
            yield r
