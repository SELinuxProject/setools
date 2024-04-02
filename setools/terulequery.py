# Copyright 2014-2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#

from collections.abc import Iterable
import typing

from . import exception, mixins, policyrep, query, util
from .descriptors import CriteriaDescriptor, CriteriaSetDescriptor

__all__: typing.Final[tuple[str, ...]] = ("TERuleQuery",)


class TERuleQuery(mixins.MatchObjClass, mixins.MatchPermission, query.PolicyQuery):

    """
    Query the Type Enforcement rules.

    Parameter:
    policy            The policy to query.

    Keyword Parameters/Class attributes:
    ruletype          The list of rule type(s) to match.
    source            The name of the source type/attribute to match.
    source_indirect   If true, members of an attribute will be
                      matched rather than the attribute itself.
                      Default is true.
    source_regex      If true, regular expression matching will
                      be used on the source type/attribute.
                      Obeys the source_indirect option.
                      Default is false.
    target            The name of the target type/attribute to match.
    target_indirect   If true, members of an attribute will be
                      matched rather than the attribute itself.
                      Default is true.
    target_regex      If true, regular expression matching will
                      be used on the target type/attribute.
                      Obeys target_indirect option.
                      Default is false.
    tclass            The object class(es) to match.
    tclass_regex      If true, use a regular expression for
                      matching the rule's object class.
                      Default is false.
    perms             The set of permission(s) to match.
    perms_equal       If true, the permission set of the rule
                      must exactly match the permissions
                      criteria.  If false, any set intersection
                      will match.
                      Default is false.
    perms_regex       If true, regular expression matching will be used
                      on the permission names instead of set logic.
                      Default is false.
    perms_subset      If true, the rule matches if the permissions criteria
                      is a subset of the rule's permission set.
                      Default is false.
    default           The name of the default type to match.
    default_regex     If true, regular expression matching will be
                      used on the default type.
                      Default is false.
    boolean           The set of boolean(s) to match.
    boolean_regex     If true, regular expression matching will be
                      used on the booleans.
                      Default is false.
    boolean_equal     If true, the booleans in the conditional
                      expression of the rule must exactly match the
                      criteria.  If false, any set intersection
                      will match.  Default is false.
    """

    ruletype = CriteriaSetDescriptor[policyrep.TERuletype](enum_class=policyrep.TERuletype)
    source = CriteriaDescriptor[policyrep.TypeOrAttr]("source_regex", "lookup_type_or_attr")
    source_regex: bool = False
    source_indirect: bool = True
    target = CriteriaDescriptor[policyrep.TypeOrAttr]("target_regex", "lookup_type_or_attr")
    target_regex: bool = False
    target_indirect: bool = True
    default = CriteriaDescriptor[policyrep.Type]("default_regex", "lookup_type_or_attr")
    default_regex: bool = False
    boolean = CriteriaSetDescriptor[policyrep.Boolean]("boolean_regex", "lookup_boolean")
    boolean_regex: bool = False
    boolean_equal: bool = False
    _xperms: policyrep.IoctlSet | None = None
    xperms_equal: bool = False

    @property
    def xperms(self) -> policyrep.IoctlSet | None:
        return self._xperms

    @xperms.setter
    def xperms(self, value: Iterable[tuple[int, int]] | None) -> None:
        if value:
            pending_xperms = set[int]()

            for low, high in value:
                if not (0 <= low <= 0xffff):
                    raise ValueError(f"{low:#07x} is not a valid ioctl.")

                if not (0 <= high <= 0xffff):
                    raise ValueError(f"{high:#07x} is not a valid ioctl.")

                if high < low:
                    high, low = low, high

                pending_xperms.update(i for i in range(low, high + 1))

            self._xperms = policyrep.IoctlSet(pending_xperms)
        else:
            self._xperms = None

    def results(self) -> Iterable[policyrep.AnyTERule]:
        """Generator which yields all matching TE rules."""
        self.log.info(f"Generating TE rule results from {self.policy}")
        self.log.debug(f"{self.ruletype=}")
        self.log.debug(f"{self.source=}, {self.source_indirect=}, {self.source_regex=}")
        self.log.debug(f"{self.target=}, {self.target_indirect=}, {self.target_regex=}")
        self._match_object_class_debug(self.log)
        self._match_perms_debug(self.log)
        self.log.debug(f"{self.xperms=}, {self.xperms_equal=}")
        self.log.debug(f"{self.default=}, {self.default_regex=}")
        self.log.debug(f"{self.boolean=}, {self.boolean_equal=}, {self.boolean_regex=}")

        for rule in self.policy.terules():
            #
            # Matching on rule type
            #
            if self.ruletype:
                if rule.ruletype not in self.ruletype:
                    continue

            #
            # Matching on source type
            #
            if self.source and not util.match_indirect_regex(
                    rule.source,
                    self.source,
                    self.source_indirect,
                    self.source_regex):
                continue

            #
            # Matching on target type
            #
            if self.target and not util.match_indirect_regex(
                    rule.target,
                    self.target,
                    self.target_indirect,
                    self.target_regex):
                continue

            #
            # Matching on object class
            #
            if not self._match_object_class(rule):
                continue

            #
            # Matching on permission set
            #
            try:
                if self.perms and rule.extended:
                    if self.perms_equal and len(self.perms) > 1:
                        # if criteria is more than one standard permission,
                        # extended perm rules can never match if the
                        # permission set equality option is on.
                        continue

                    assert isinstance(rule, policyrep.AVRuleXperm), \
                        "Rule is not an extended permission rule, this is an SETools bug."
                    if rule.xperm_type not in self.perms:
                        continue
                elif not self._match_perms(rule):
                    continue
            except exception.RuleUseError:
                continue

            #
            # Matching on extended permissions
            #
            try:
                if self.xperms and not util.match_regex_or_set(
                        rule.perms,
                        self.xperms,
                        self.xperms_equal,
                        False):
                    continue

            except exception.RuleUseError:
                continue

            #
            # Matching on default type
            #
            if self.default:
                try:
                    # because default type is always a single
                    # type, hard-code indirect to True
                    # so the criteria can be an attribute
                    if not util.match_indirect_regex(
                            rule.default,
                            self.default,
                            True,
                            self.default_regex):
                        continue
                except exception.RuleUseError:
                    continue

            #
            # Match on Boolean in conditional expression
            #
            if self.boolean:
                try:
                    if not util.match_regex_or_set(
                            rule.conditional.booleans,
                            self.boolean,
                            self.boolean_equal,
                            self.boolean_regex):
                        continue
                except exception.RuleNotConditional:
                    continue

            # if we get here, we have matched all available criteria
            yield rule
