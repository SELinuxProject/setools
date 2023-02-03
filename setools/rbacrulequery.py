# Copyright 2014-2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
import logging
import re
from typing import cast, Iterable, Optional, Pattern, Union

from . import mixins, query
from .descriptors import CriteriaDescriptor, CriteriaSetDescriptor
from .exception import InvalidType, RuleUseError
from .policyrep import AnyRBACRule, RBACRuletype, Role, TypeOrAttr
from .util import match_indirect_regex


class RBACRuleQuery(mixins.MatchObjClass, query.PolicyQuery):

    """
    Query the RBAC rules.

    Parameter:
    policy            The policy to query.

    Keyword Parameters/Class attributes:
    ruletype        The list of rule type(s) to match.
    source          The name of the source role/attribute to match.
    source_indirect If true, members of an attribute will be
                    matched rather than the attribute itself.
    source_regex    If true, regular expression matching will
                    be used on the source role/attribute.
                    Obeys the source_indirect option.
    target          The name of the target role/attribute to match.
    target_indirect If true, members of an attribute will be
                    matched rather than the attribute itself.
    target_regex    If true, regular expression matching will
                    be used on the target role/attribute.
                    Obeys target_indirect option.
    tclass          The object class(es) to match.
    tclass_regex    If true, use a regular expression for
                    matching the rule's object class.
    default         The name of the default role to match.
    default_regex   If true, regular expression matching will
                    be used on the default role.
    """

    ruletype = CriteriaSetDescriptor(enum_class=RBACRuletype)
    source = CriteriaDescriptor("source_regex", "lookup_role")
    source_regex: bool = False
    source_indirect: bool = True
    _target: Optional[Union[Pattern, Role, TypeOrAttr]] = None
    target_regex: bool = False
    target_indirect: bool = True
    tclass = CriteriaSetDescriptor("tclass_regex", "lookup_class")
    tclass_regex: bool = False
    default = CriteriaDescriptor("default_regex", "lookup_role")
    default_regex: bool = False

    @property
    def target(self) -> Optional[Union[Pattern, Role, TypeOrAttr]]:
        return self._target

    @target.setter
    def target(self, value: Optional[Union[str, Role, TypeOrAttr]]) -> None:
        if not value:
            self._target = None
        elif self.target_regex:
            self._target = re.compile(value)
        else:
            try:
                self._target = self.policy.lookup_type_or_attr(cast(Union[str, TypeOrAttr], value))
            except InvalidType:
                self._target = self.policy.lookup_role(cast(Union[str, Role], value))

    def __init__(self, policy, **kwargs) -> None:
        super(RBACRuleQuery, self).__init__(policy, **kwargs)
        self.log = logging.getLogger(__name__)

    def results(self) -> Iterable[AnyRBACRule]:
        """Generator which yields all matching RBAC rules."""
        self.log.info("Generating RBAC rule results from {0.policy}".format(self))
        self.log.debug("Ruletypes: {0.ruletype}".format(self))
        self.log.debug("Source: {0.source!r}, indirect: {0.source_indirect}, "
                       "regex: {0.source_regex}".format(self))
        self.log.debug("Target: {0.target!r}, indirect: {0.target_indirect}, "
                       "regex: {0.target_regex}".format(self))
        self._match_object_class_debug(self.log)
        self.log.debug("Default: {0.default!r}, regex: {0.default_regex}".format(self))

        for rule in self.policy.rbacrules():
            #
            # Matching on rule type
            #
            if self.ruletype:
                if rule.ruletype not in self.ruletype:
                    continue

            #
            # Matching on source role
            #
            if self.source and not match_indirect_regex(
                    rule.source,
                    self.source,
                    self.source_indirect,
                    self.source_regex):
                continue

            #
            # Matching on target type (role_transition)/role(allow)
            #
            if self.target and not match_indirect_regex(
                    rule.target,
                    self.target,
                    self.target_indirect,
                    self.target_regex):
                continue

            #
            # Matching on object class
            #
            try:
                if not self._match_object_class(rule):
                    continue
            except RuleUseError:
                continue

            #
            # Matching on default role
            #
            if self.default:
                try:
                    # because default role is always a single
                    # role, hard-code indirect to True
                    # so the criteria can be an attribute
                    if not match_indirect_regex(
                            rule.default,
                            self.default,
                            True,
                            self.default_regex):
                        continue
                except RuleUseError:
                    continue

            # if we get here, we have matched all available criteria
            yield rule
