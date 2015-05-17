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
# pylint: disable=attribute-defined-outside-init,no-member
import re

from . import query
from .descriptors import CriteriaDescriptor


class ContextQuery(query.PolicyQuery):

    """
    Base class for SETools in-policy labeling/context queries.

    Parameter:
    policy          The policy to query.

    Keyword Parameters/Class attributes:
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

    user = CriteriaDescriptor("user_regex", "lookup_user")
    user_regex = False
    role = CriteriaDescriptor("role_regex", "lookup_role")
    role_regex = False
    type_ = CriteriaDescriptor("type_regex", "lookup_type")
    type_regex = False
    range_ = CriteriaDescriptor(lookup_function="lookup_range")
    range_overlap = False
    range_subset = False
    range_superset = False
    range_proper = False

    def _match_context(self, context):

        if self.user and not query.PolicyQuery._match_regex(
                context.user,
                self.user,
                self.user_regex):
            return False

        if self.role and not query.PolicyQuery._match_regex(
                context.role,
                self.role,
                self.role_regex):
            return False

        if self.type_ and not query.PolicyQuery._match_regex(
                context.type_,
                self.type_,
                self.type_regex):
            return False

        if self.range_ and not query.PolicyQuery._match_range(
                context.range_,
                self.range_,
                self.range_subset,
                self.range_overlap,
                self.range_superset,
                self.range_proper):
            return False

        return True
