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


class ValidatetransQuery(mixins.MatchObjClass, PolicyQuery):

    """Query validatetrans rules (validatetrans/mlsvalidatetrans)."""

    def __init__(self, policy,
                 ruletype=[],
                 tclass="", tclass_regex=False,
                 role="", role_regex=False, role_indirect=True,
                 type_="", type_regex=False, type_indirect=True,
                 user="", user_regex=False):

        """
        Parameter:
        policy            The policy to query.
        ruletype          The rule type(s) to match.
        tclass            The object class(es) to match.
        tclass_regex      If true, use a regular expression for
                          matching the rule's object class.
        role              The name of the role to match in the
                          constraint expression.
        role_indirect     If true, members of an attribute will be
                          matched rather than the attribute itself.
        role_regex        If true, regular expression matching will
                          be used on the role.
        type_             The name of the type/attribute to match in the
                          constraint expression.
        type_indirect     If true, members of an attribute will be
                          matched rather than the attribute itself.
        type_regex        If true, regular expression matching will
                          be used on the type/attribute.
        user              The name of the user to match in the
                          constraint expression.
        user_regex        If true, regular expression matching will
                          be used on the user.
        """

        self.policy = policy

        self.set_ruletype(ruletype)
        self.set_tclass(tclass, regex=tclass_regex)
        self.set_role(role, regex=role_regex, indirect=role_indirect)
        self.set_type(type_, regex=type_regex, indirect=type_indirect)
        self.set_user(user, regex=user_regex)

    def _match_expr(self, expr, criteria, indirect, regex):
        """
        Match roles/types/users in a constraint expression,
        optionally by expanding the contents of attributes.

        Parameters:
        expr        The expression to match.
        criteria    The criteria to match.
        indirect    If attributes in the expression should be expanded.
        regex       If regular expression matching should be used.
        """

        if indirect:
            obj = set()
            for item in expr:
                obj.update(item.expand())
        else:
            obj = expr

        return self._match_in_set(obj, criteria, regex)

    def results(self):
        """Generator which yields all matching constraints rules."""

        for c in self.policy.validatetrans():
            if self.ruletype:
                if c.ruletype not in self.ruletype:
                    continue

            if self.tclass and not self._match_object_class(c.tclass):
                continue

            if self.role and not self._match_expr(
                        c.roles,
                        self.role_cmp,
                        self.role_indirect,
                        self.role_regex):
                    continue

            if self.type_ and not self._match_expr(
                        c.types,
                        self.type_cmp,
                        self.type_indirect,
                        self.type_regex):
                    continue

            if self.user and not self._match_expr(
                        c.users,
                        self.user_cmp,
                        False,
                        self.user_regex):
                    continue

            yield c

    def set_ruletype(self, ruletype):
        """
        Set the rule types for the rule query.

        Parameter:
        ruletype    The rule types to match.
        """

        self.ruletype = ruletype

    def set_role(self, role, **opts):
        """
        Set the criteria for matching the constraint's role.

        Parameter:
        role       Name to match the constraint's role.
        regex      If true, regular expression matching will be used.

        Exceptions:
        NameError  Invalid keyword option.
        """

        self.role = role

        for k in list(opts.keys()):
            if k == "regex":
                self.role_regex = opts[k]
            elif k == "indirect":
                self.role_indirect = opts[k]
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
        Set the criteria for matching the constraint's type.

        Parameter:
        type_      Name to match the constraint's type.
        regex      If true, regular expression matching will be used.

        Exceptions:
        NameError  Invalid keyword option.
        """

        self.type_ = type_

        for k in list(opts.keys()):
            if k == "regex":
                self.type_regex = opts[k]
            elif k == "indirect":
                self.type_indirect = opts[k]
            else:
                raise NameError("Invalid name option: {0}".format(k))

        if not self.type_:
            self.type_cmp = None
        elif self.type_regex:
            self.type_cmp = re.compile(self.type_)
        else:
            self.type_cmp = self.policy.lookup_type(type_)

    def set_user(self, user, **opts):
        """
        Set the criteria for matching the constraint's user.

        Parameter:
        user       Name to match the constraint's user.
        regex      If true, regular expression matching will be used.

        Exceptions:
        NameError  Invalid keyword option.
        """

        self.user = user

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
