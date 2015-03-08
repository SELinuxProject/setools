# Copyright 2015, Tresys Technology, LLC
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

from . import mixins
from .query import PolicyQuery


class ConstraintQuery(mixins.MatchObjClass, mixins.MatchPermission, PolicyQuery):

    """Query constraint rules (constraint/mlsconstraint)."""

    def __init__(self, policy,
                 ruletype=[],
                 tclass="", tclass_regex=False,
                 perms=set(), perms_equal=False):

        """
        Parameter:
        policy            The policy to query.
        ruletype          The rule type(s) to match.
        tclass            The object class(es) to match.
        tclass_regex      If true, use a regular expression for
                          matching the rule's object class.
        perms             The permission(s) to match.
        perms_equal       If true, the permission set of the rule
                          must exactly match the permissions
                          criteria.  If false, any set intersection
                          will match.
        """

        self.policy = policy

        self.set_ruletype(ruletype)
        self.set_tclass(tclass, regex=tclass_regex)
        self.set_perms(perms, equal=perms_equal)

    def results(self):
        """Generator which yields all matching constraints rules."""

        for c in self.policy.constraints():
            if self.ruletype:
                if c.ruletype not in self.ruletype:
                    continue

            if self.tclass and not self._match_object_class(c.tclass):
                continue

            if self.perms and not self._match_perms(c.perms):
                continue

            yield c

    def set_ruletype(self, ruletype):
        """
        Set the rule types for the rule query.

        Parameter:
        ruletype    The rule types to match.
        """

        self.ruletype = ruletype
