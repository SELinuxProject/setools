# Copyright 2020, Microsoft Corporation
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

from ..exception import InvalidType, InvalidCheckValue
from .checkermodule import CheckerModule


ATTR_OPT = "attr"
MISSINOK_OPT = "missing_ok"


class EmptyTypeAttr(CheckerModule):

    """Checker module for asserting a type attribute is empty."""

    check_type = "empty_typeattr"
    check_config = frozenset((ATTR_OPT, MISSINOK_OPT))

    def __init__(self, policy, checkname, config):
        super().__init__(policy, checkname, config)
        self.log = logging.getLogger(__name__)

        # this will make the check pass automatically
        # since the attribute is missing.  Only set if
        # missing_ok is True AND attr is missing.
        self.pass_by_missing = False

        missing_ok = config.get(MISSINOK_OPT)
        if missing_ok and missing_ok.strip().lower() in ("yes", "true", "1"):
            self.missing_ok = True
        else:
            self.missing_ok = False

        try:
            attr = config.get(ATTR_OPT)
            if not attr:
                raise InvalidCheckValue("{}: \"{}\" setting is missing.".format(self.checkname,
                                                                                ATTR_OPT))

            self.attr = self.policy.lookup_typeattr(attr)
        except InvalidType as e:
            if not self.missing_ok:
                raise InvalidCheckValue("attr setting error: {}".format(e)) from e
            else:
                self.pass_by_missing = True
                self.attr = attr

    def run(self):
        self.log.info("Checking type attribute {} is empty.".format(self.attr))

        failures = []

        if self.pass_by_missing:
            self.log_info("    {} does not exist.".format(self.attr))
        else:
            self.output.write("Member types of {}:\n".format(self.attr))

            types = sorted(self.attr.expand())
            if types:
                for type_ in types:
                    self.log_fail(type_.name)
                    failures.append(type_)
            else:
                self.log_ok("    <empty>")

        self.log.debug("{} failure(s)".format(failures))
        return failures
