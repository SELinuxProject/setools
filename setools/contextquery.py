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

from . import query


class ContextQuery(query.PolicyQuery):

    """Abstract base class for SETools in-policy labeling/context queries."""

    @staticmethod
    def _match_context(context,
                       user, user_regex,
                       role, role_regex,
                       type_, type_regex,
                       range_, range_subset, range_overlap, range_superset, range_proper):
        """
        Match the context with optional regular expression.

        Parameters:
        context         The object to match.
        user            The user to match in the context.
        user_regex      If true, regular expression matching
                        will be used on the user.
        role            The role to match in the context.
        role_regex      If true, regular expression matching
                        will be used on the role.
        type_           The type to match in the context.
        type_regex      If true, regular expression matching
                        will be used on the type.
        range_          The range to match in the context.
        range_subset    If true, the criteria will match if it
                        is a subset of the context's range.
        range_overlap   If true, the criteria will match if it
                        overlaps any of the context's range.
        range_superset  If true, the criteria will match if it
                        is a superset of the context's range.
        range_proper    If true, use proper superset/subset
                        on range matching operations.
                        No effect if not using set operations.
        """

        if user and not query.PolicyQuery._match_regex(
                context.user,
                user,
                user_regex):
            return False

        if role and not query.PolicyQuery._match_regex(
                context.role,
                role,
                role_regex):
            return False

        if type_ and not query.PolicyQuery._match_regex(
                context.type_,
                type_,
                type_regex):
            return False

        if range_ and not query.PolicyQuery._match_range(
                (context.range_.low, context.range_.high),
                (range_.low, range_.high),
                range_subset,
                range_overlap,
                range_superset,
                range_proper):
            return False

        return True

    def set_user(self, user, **opts):
        """
        Set the criteria for matching the context's user.

        Parameter:
        user       Name to match the context's user.
        regex      If true, regular expression matching will be used.

        Exceptions:
        NameError  Invalid keyword option.
        """

        self.user = str(user)

        for k in list(opts.keys()):
            if k == "regex":
                self.user_regex = opts[k]
            else:
                raise NameError("Invalid name option: {0}".format(k))

        if not self.user:
            self.user_cmp = None
        elif self.user_regex:
            self.user_cmp = re.compile(self.user)
        else:
            self.user_cmp = self.policy.lookup_user(self.user)

    def set_role(self, role, **opts):
        """
        Set the criteria for matching the context's role.

        Parameter:
        role       Name to match the context's role.
        regex      If true, regular expression matching will be used.

        Exceptions:
        NameError  Invalid keyword option.
        """

        self.role = str(role)

        for k in list(opts.keys()):
            if k == "regex":
                self.role_regex = opts[k]
            else:
                raise NameError("Invalid name option: {0}".format(k))

        if not self.role:
            self.role_cmp = None
        elif self.role_regex:
            self.role_cmp = re.compile(self.role)
        else:
            self.role_cmp = self.policy.lookup_role(self.role)

    def set_type(self, type_, **opts):
        """
        Set the criteria for matching the context's type.

        Parameter:
        type_      Name to match the context's type.
        regex      If true, regular expression matching will be used.

        Exceptions:
        NameError  Invalid keyword option.
        """

        self.type_ = str(type_)

        for k in list(opts.keys()):
            if k == "regex":
                self.type_regex = opts[k]
            else:
                raise NameError("Invalid name option: {0}".format(k))

        if not self.type_:
            self.type_cmp = None
        elif self.type_regex:
            self.type_cmp = re.compile(self.type_)
        else:
            self.type_cmp = self.policy.lookup_type(type_)

    def set_range(self, range_, **opts):
        """
        Set the criteria for matching the context's range.

        Parameter:
        range_      Criteria to match the context's range.

        Keyword Parameters:
        subset      If true, the criteria will match if it is a subset
                    of the context's range.
        overlap     If true, the criteria will match if it overlaps
                    any of the context's range.
        superset    If true, the criteria will match if it is a superset
                    of the context's range.
        proper      If true, use proper superset/subset operations.
                    No effect if not using set operations.

        Exceptions:
        NameError   Invalid keyword option.
        """

        self.range_ = range_

        for k in list(opts.keys()):
            if k == "subset":
                self.range_subset = opts[k]
            elif k == "overlap":
                self.range_overlap = opts[k]
            elif k == "superset":
                self.range_superset = opts[k]
            elif k == "proper":
                self.range_proper = opts[k]
            else:
                raise NameError("Invalid name option: {0}".format(k))

        if self.range_:
            self.range_cmp = self.policy.lookup_range(self.range_)
        else:
            self.range_cmp = None
