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

from . import query


class ContextQuery(query.PolicyQuery):

    """Abstract base class for SETools in-policy labeling/context queries."""

    @staticmethod
    def _match_context(context,
                       user, user_regex, user_recomp,
                       role, role_regex, role_recomp,
                       type_, type_regex, type_recomp,
                       range_):
        """
        Match the context with optional regular expression.

        Parameters:
        context         The object to match.
        user            The user to match in the context.
        user_regex      If true, regular expression matching
                        will be used on the user.
        user_recomp     The compiled user regular expression.
        role            The role to match in the context.
        role_regex      If true, regular expression matching
                        will be used on the role.
        role_recomp     The compiled role regular expression.
        type_           The type to match in the context.
        type_regex      If true, regular expression matching
                        will be used on the type.
        type_recomp     The compiled type regular expression.
        range_          The range to match in the context.
        """

        if user and not query.PolicyQuery._match_regex(
                context.user,
                user,
                user_regex,
                user_recomp):
            return False

        if role and not query.PolicyQuery._match_regex(
                context.role,
                role,
                role_regex,
                role_recomp):
            return False

        if type_ and not query.PolicyQuery._match_regex(
                context.type_,
                type_,
                type_regex,
                type_recomp):
            return False

        if range_:
            raise NotImplementedError(
                "Context range queries are not yet implemented.")

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

        for k in opts.keys():
            if k == "regex":
                self.user_regex = opts[k]
            else:
                raise NameError("Invalid name option: {0}".format(k))

        if self.user_regex:
            self.user_cmp = re.compile(self.user)
        else:
            self.user_cmp = None

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

        for k in opts.keys():
            if k == "regex":
                self.role_regex = opts[k]
            else:
                raise NameError("Invalid name option: {0}".format(k))

        if self.role_regex:
            self.role_cmp = re.compile(self.role)
        else:
            self.role_cmp = None

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

        for k in opts.keys():
            if k == "regex":
                self.type_regex = opts[k]
            else:
                raise NameError("Invalid name option: {0}".format(k))

        if self.type_regex:
            self.type_cmp = re.compile(self.type_)
        else:
            self.type_cmp = None

    def set_range(self, range_, **opts):
        """
        Set the criteria for matching the context's range.

        Parameter:
        range_     Range to match the context's range.

        Exceptions:
        NameError  Invalid keyword option.
        """

        self.range_ = range_
