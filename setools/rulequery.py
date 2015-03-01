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
import re

from .query import PolicyQuery


class RuleQuery(PolicyQuery):

    """Abstract base class for rule queries."""

    @staticmethod
    def _match_indirect_regex(obj, criteria, indirect, regex):
        """
        Match the object with optional regular expression and indirection.

        Parameters:
        obj         The object to match.
        criteria    The criteria to match.
        regex       If regular expression matching should be used.
        indirect    If object indirection should be	used, e.g.
                    expanding an attribute.
        """

        if indirect:
            return PolicyQuery._match_in_set(
                (obj.expand()),
                criteria,
                regex)
        else:
            return PolicyQuery._match_regex(
                obj,
                criteria,
                regex)

    @staticmethod
    def _match_object_class(obj, criteria, regex):
        """
        Match the object class with optional regular expression.

        Parameters:
        obj         The object to match.
        criteria    The criteria to match.
        regex       If regular expression matching should be used.
        """

        if isinstance(criteria, set):
            return (obj in criteria)
        elif regex:
            return bool(criteria.search(str(obj)))
        else:
            return (obj == criteria)

    def set_ruletype(self, ruletype):
        """
        Set the rule types for the rule query.

        Parameter:
        ruletype    The rule types to match.
        """

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
        NameError	Invalid keyword option.
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
            self.source_cmp = self.policy.lookup_type_or_typeattr(self.source)

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
        NameError	Invalid keyword option.
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
            self.target_cmp = self.policy.lookup_type_or_typeattr(self.target)

    def set_tclass(self, tclass, **opts):
        """
        Set the object class(es) for the rule query.

        Parameter:
        tclass	    The name of the object classes to match.
                    This must be a string if regular expression
                    matching is used.

        Keyword Options:
        regex       If true, use a regular expression for
                    matching the object class. If false, any
                    set intersection will match.

        Exceptions:
        NameError   Invalid keyword option.
        """

        self.tclass = tclass

        for k in list(opts.keys()):
            if k == "regex":
                self.tclass_regex = opts[k]
            else:
                raise NameError("Invalid object class option: {0}".format(k))

        if not self.tclass:
            self.tclass_cmp = None
        elif self.tclass_regex:
            self.tclass_cmp = re.compile(self.tclass)
        elif isinstance(self.tclass, str):
            self.tclass_cmp = self.policy.lookup_class(self.tclass)
        else:
            self.tclass_cmp = set(self.policy.lookup_class(c) for c in self.tclass)

    def set_default(self, default, **opts):
        raise NotImplementedError
