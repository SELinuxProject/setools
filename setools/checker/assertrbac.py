# Copyright 2020, Microsoft Corporation
# Copyright 2020, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: LGPL-2.1-only
#

import logging
from typing import List, Union

from ..exception import InvalidCheckValue
from ..policyrep import AnyRBACRule
from ..rbacrulequery import RBACRuleQuery
from .checkermodule import CheckerModule
from .descriptors import ConfigDescriptor, ConfigSetDescriptor

SOURCE_OPT = "source"
TARGET_OPT = "target"
EXEMPT_SRC_OPT = "exempt_source"
EXEMPT_TGT_OPT = "exempt_target"
EXPECT_SRC_OPT = "expect_source"
EXPECT_TGT_OPT = "expect_target"


class AssertRBAC(CheckerModule):

    """Checker module for asserting a RBAC allow rule exists (or not)."""

    check_type = "assert_rbac"
    check_config = frozenset((SOURCE_OPT, TARGET_OPT, EXEMPT_SRC_OPT, EXEMPT_TGT_OPT,
                              EXPECT_SRC_OPT, EXPECT_TGT_OPT))

    source = ConfigDescriptor("lookup_role")
    target = ConfigDescriptor("lookup_role")

    exempt_source = ConfigSetDescriptor("lookup_role", strict=False, expand=True)
    exempt_target = ConfigSetDescriptor("lookup_role", strict=False, expand=True)
    expect_source = ConfigSetDescriptor("lookup_role", strict=True, expand=True)
    expect_target = ConfigSetDescriptor("lookup_role", strict=True, expand=True)

    def __init__(self, policy, checkname, config) -> None:
        super().__init__(policy, checkname, config)
        self.log = logging.getLogger(__name__)

        self.source = config.get(SOURCE_OPT)
        self.target = config.get(TARGET_OPT)

        self.exempt_source = config.get(EXEMPT_SRC_OPT)
        self.exempt_target = config.get(EXEMPT_TGT_OPT)
        self.expect_source = config.get(EXPECT_SRC_OPT)
        self.expect_target = config.get(EXPECT_TGT_OPT)

        if not any((self.source, self.target)):
            raise InvalidCheckValue(
                "At least one of source or target options must be set.")

        source_exempt_expect_overlap = self.exempt_source & self.expect_source
        if source_exempt_expect_overlap:
            self.log.info("Overlap in expect_source and exempt_source: {}".
                          format(", ".join(i.name for i in source_exempt_expect_overlap)))

        target_exempt_expect_overlap = self.exempt_target & self.expect_target
        if target_exempt_expect_overlap:
            self.log.info("Overlap in expect_target and exempt_target: {}".
                          format(", ".join(i.name for i in target_exempt_expect_overlap)))

    def run(self) -> List:
        assert any((self.source, self.target)), "AssertRBAC no options set, this is a bug."

        self.log.info("Checking RBAC allow rule assertion.")

        query = RBACRuleQuery(self.policy,
                              source=self.source,
                              target=self.target,
                              ruletype=("allow",))

        unseen_sources = set(self.expect_source)
        unseen_targets = set(self.expect_target)
        failures: List[Union[AnyRBACRule, str]] = []
        for rule in sorted(query.results()):
            srcs = set(rule.source.expand())
            tgts = set(rule.target.expand())

            unseen_sources -= srcs
            unseen_targets -= tgts
            if (srcs - self.expect_source - self.exempt_source) and \
                    (tgts - self.expect_target - self.exempt_target):

                self.log_fail(str(rule))
                failures.append(rule)
            else:
                self.log_ok(str(rule))

        for item in unseen_sources:
            failure = "Expected rule with source \"{}\" not found.".format(item)
            self.log_fail(failure)
            failures.append(failure)

        for item in unseen_targets:
            failure = "Expected rule with target \"{}\" not found.".format(item)
            self.log_fail(failure)
            failures.append(failure)

        self.log.debug("{} failure(s)".format(failures))
        return failures
