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
# pylint: disable=no-member,attribute-defined-outside-init,abstract-method
import re

from . import mixins
from .query import PolicyQuery


class RuleQuery(mixins.MatchObjClass, PolicyQuery):

    """Abstract base class for rule queries."""

    @staticmethod
    def _match_indirect_regex(obj, criteria, indirect, regex):
        """
        Match the object with optional regular expression and indirection.

        Parameters:
        obj         The object to match.
        criteria    The criteria to match.
        regex       If regular expression matching should be used.
        indirect    If object indirection should be used, e.g.
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

    def set_ruletype(self, ruletype):
        raise NotImplementedError

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
            self.source_cmp = self.policy.lookup_type_or_attr(self.source)

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
            self.target_cmp = self.policy.lookup_type_or_attr(self.target)

    def set_default(self, default, **opts):
        raise NotImplementedError
