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
from . import rulequery


class MLSRuleQuery(rulequery.RuleQuery):

    """Query MLS rules."""

    def __init__(self, policy,
                 ruletype=[],
                 source="", source_regex=False,
                 target="", target_regex=False,
                 tclass="", tclass_regex=False):
        """
        Parameters:
        policy           The policy to query.
        ruletype         The rule type(s) to match.
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

        self.policy = policy

        self.set_ruletype(ruletype)
        self.set_source(source, regex=source_regex)
        self.set_target(target, regex=target_regex)
        self.set_tclass(tclass, regex=tclass_regex)

    def results(self):
        """Generator which yields all matching MLS rules."""

        for r in self.policy.mlsrules():
            #
            # Matching on rule type
            #
            if self.ruletype:
                if not r.ruletype in self.ruletype:
                    continue

            #
            # Matching on source type
            #
            if self.source and not self._match_regex(
                    r.source,
                    self.source,
                    self.source_regex,
                    self.source_cmp):
                continue

            #
            # Matching on target type
            #
            if self.target and not self._match_regex(
                    r.target,
                    self.target,
                    self.target_regex,
                    self.target_cmp):
                continue

            #
            # Matching on object class
            #
            if self.tclass and not self._match_object_class(
                    r.tclass,
                    self.tclass,
                    self.tclass_regex,
                    self.tclass_cmp):
                continue

            # TODO: something with the range

            # if we get here, we have matched all available criteria
            yield r
