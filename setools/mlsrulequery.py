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
from . import rulequery


class MLSRuleQuery(rulequery.RuleQuery):

    """Query MLS rules."""

    def __init__(self, policy,
                 ruletype=[],
                 source="", source_regex=False,
                 target="", target_regex=False,
                 tclass="", tclass_regex=False,
                 default="", default_overlap=False, default_subset=False,
                 default_superset=False, default_proper=False):
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
        self.set_default(default, overlap=default_overlap, subset=default_subset,
                         superset=default_superset, proper=default_proper)

    def results(self):
        """Generator which yields all matching MLS rules."""

        for r in self.policy.mlsrules():
            #
            # Matching on rule type
            #
            if self.ruletype:
                if r.ruletype not in self.ruletype:
                    continue

            #
            # Matching on source type
            #
            if self.source and not self._match_regex(
                    r.source,
                    self.source_cmp,
                    self.source_regex):
                continue

            #
            # Matching on target type
            #
            if self.target and not self._match_regex(
                    r.target,
                    self.target_cmp,
                    self.target_regex):
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
            # Matching on range
            #
            if self.default and not self._match_range(
                    (r.default.low, r.default.high),
                    (self.default_cmp.low, self.default_cmp.high),
                    self.default_subset,
                    self.default_overlap,
                    self.default_superset,
                    self.default_proper):
                continue

            # if we get here, we have matched all available criteria
            yield r

    def set_default(self, default, **opts):
        """
        Set the criteria for matching the rule's default range.

        Parameter:
        default     Criteria to match the rule's default range.

        Keyword Parameters:
        subset      If true, the criteria will match if it is a subset
                    of the rule's default range.
        overlap     If true, the criteria will match if it overlaps
                    any of the rule's default range.
        superset    If true, the criteria will match if it is a superset
                    of the rule's default range.
        proper      If true, use proper superset/subset operations.
                    No effect if not using set operations.

        Exceptions:
        NameError   Invalid keyword option.
        """

        self.default = default

        for k in list(opts.keys()):
            if k == "subset":
                self.default_subset = opts[k]
            elif k == "overlap":
                self.default_overlap = opts[k]
            elif k == "superset":
                self.default_superset = opts[k]
            elif k == "proper":
                self.default_proper = opts[k]
            else:
                raise NameError("Invalid name option: {0}".format(k))

        if not self.default:
            self.default_cmp = None
        else:
            self.default_cmp = self.policy.lookup_range(self.default)
