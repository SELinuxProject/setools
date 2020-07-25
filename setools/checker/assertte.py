# Copyright 2020, Microsoft Corporation
# Copyright 2020, Chris PeBenito <pebenito@ieee.org>
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

import logging

from ..exception import InvalidCheckValue, InvalidClass
from ..terulequery import TERuleQuery
from .checkermodule import CheckerModule
from .util import config_list_to_class, config_list_to_perms, config_list_to_types_or_attrs, \
    config_to_type_or_attr


SOURCE_OPT = "source"
TARGET_OPT = "target"
CLASS_OPT = "tclass"
PERMS_OPT = "perms"
EXEMPT_SRC_OPT = "exempt_source"
EXEMPT_TGT_OPT = "exempt_target"
EXPECT_SRC_OPT = "expect_source"
EXPECT_TGT_OPT = "expect_target"


class AssertTE(CheckerModule):

    """Checker module for asserting a type enforcement allow rule exists (or not)."""

    check_type = "assert_te"
    check_config = frozenset((SOURCE_OPT, TARGET_OPT, CLASS_OPT, PERMS_OPT, EXEMPT_SRC_OPT,
                              EXEMPT_TGT_OPT, EXPECT_SRC_OPT, EXPECT_TGT_OPT))

    def __init__(self, policy, checkname, config):
        super().__init__(policy, checkname, config)
        self.log = logging.getLogger(__name__)

        self.source = config_to_type_or_attr(self.policy, config.get(SOURCE_OPT))
        self.target = config_to_type_or_attr(self.policy, config.get(TARGET_OPT))
        self.tclass = config_list_to_class(self.policy, config.get(CLASS_OPT))
        self.perms = config_list_to_perms(self.policy, config.get(PERMS_OPT), self.tclass)

        self.exempt_source = config_list_to_types_or_attrs(self.log,
                                                           self.policy,
                                                           config.get(EXEMPT_SRC_OPT),
                                                           strict=False,
                                                           expand=True)

        self.exempt_target = config_list_to_types_or_attrs(self.log,
                                                           self.policy,
                                                           config.get(EXEMPT_TGT_OPT),
                                                           strict=False,
                                                           expand=True)

        self.expect_source = config_list_to_types_or_attrs(self.log,
                                                           self.policy,
                                                           config.get(EXPECT_SRC_OPT),
                                                           strict=True,
                                                           expand=True)

        self.expect_target = config_list_to_types_or_attrs(self.log,
                                                           self.policy,
                                                           config.get(EXPECT_TGT_OPT),
                                                           strict=True,
                                                           expand=True)

        if not any((self.source, self.target, self.tclass, self.perms)):
            raise InvalidCheckValue(
                "At least one of source, target, tclass, or perms options must be set.")

        source_exempt_expect_overlap = self.exempt_source & self.expect_source
        if source_exempt_expect_overlap:
            self.log.info("Overlap in expect_source and exempt_source: {}".
                          format(", ".join(i.name for i in source_exempt_expect_overlap)))

        target_exempt_expect_overlap = self.exempt_target & self.expect_target
        if target_exempt_expect_overlap:
            self.log.info("Overlap in expect_target and exempt_target: {}".
                          format(", ".join(i.name for i in target_exempt_expect_overlap)))

    def run(self):
        assert any((self.source, self.target, self.tclass, self.perms)), \
            "AssertTe no options set, this is a bug."

        self.log.info("Checking TE allow rule assertion.")

        query = TERuleQuery(self.policy,
                            source=self.source,
                            target=self.target,
                            tclass=self.tclass,
                            perms=self.perms,
                            ruletype=("allow",))

        unseen_sources = set(self.expect_source)
        unseen_targets = set(self.expect_target)
        failures = []
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
