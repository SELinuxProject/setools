# Copyright 2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from collections.abc import Iterable
import typing

from . import exception, mixins, policyrep, query, util
from .descriptors import CriteriaDescriptor, CriteriaSetDescriptor

__all__: typing.Final[tuple[str, ...]] = ("ConstraintQuery",)


class ConstraintQuery(mixins.MatchObjClass, mixins.MatchPermission, query.PolicyQuery):

    """
    Query constraint rules, (mls)constrain/(mls)validatetrans.

    Parameter:
    policy            The policy to query.

    Keyword Parameters/Class attributes:
    ruletype          The list of rule type(s) to match.
    tclass            The object class(es) to match.
    tclass_regex      If true, use a regular expression for
                      matching the rule's object class.
    perms             The permission(s) to match.
    perms_equal       If true, the permission set of the rule
                      must exactly match the permissions
                      criteria.  If false, any set intersection
                      will match.
    perms_regex       If true, regular expression matching will be used
                      on the permission names instead of set logic.
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

    ruletype = CriteriaSetDescriptor[policyrep.ConstraintRuletype](
        enum_class=policyrep.ConstraintRuletype)
    user = CriteriaDescriptor[policyrep.User]("user_regex", "lookup_user")
    user_regex: bool = False
    role = CriteriaDescriptor[policyrep.Role]("role_regex", "lookup_role")
    role_regex: bool = False
    role_indirect: bool = True
    type_ = CriteriaDescriptor[policyrep.Type]("type_regex", "lookup_type_or_attr")
    type_regex: bool = False
    type_indirect: bool = True

    def _match_expr(self, expr: frozenset[policyrep.User] | frozenset[policyrep.Role] |
                    frozenset[policyrep.Type], criteria, indirect: bool, regex: bool) -> bool:
        """
        Match roles/types/users in a constraint expression,
        optionally by expanding the contents of attributes.

        Parameters:
        expr        The expression to match.
        criteria    The criteria to match.
        indirect    If attributes in the expression should be expanded.
        regex       If regular expression matching should be used.
        """

        obj: set | frozenset
        if indirect:
            obj = set()
            for item in expr:
                obj.update(item.expand())
        else:
            obj = expr

        return util.match_in_set(obj, criteria, regex)

    def results(self) -> Iterable[policyrep.AnyConstraint]:
        """Generator which yields all matching constraints rules."""
        self.log.info(f"Generating constraint results from {self.policy}")
        self.log.debug(f"{self.ruletype=}")
        self._match_object_class_debug(self.log)
        self._match_perms_debug(self.log)
        self.log.debug(f"{self.user=}, {self.user_regex=}")
        self.log.debug(f"{self.role=}, {self.role_regex=}")
        self.log.debug(f"{self.type_=}, {self.type_regex=}")

        for c in self.policy.constraints():
            if self.ruletype:
                if c.ruletype not in self.ruletype:
                    continue

            if not self._match_object_class(c):
                continue

            try:
                if not self._match_perms(c):
                    continue
            except exception.ConstraintUseError:
                continue

            if self.role and not self._match_expr(
                    c.expression.roles,
                    self.role,
                    self.role_indirect,
                    self.role_regex):
                continue

            if self.type_ and not self._match_expr(
                    c.expression.types,
                    self.type_,
                    self.type_indirect,
                    self.type_regex):
                continue

            if self.user and not self._match_expr(
                    c.expression.users,
                    self.user,
                    False,
                    self.user_regex):
                continue

            yield c
