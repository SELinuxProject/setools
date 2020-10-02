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

import sys
import configparser
import logging
from datetime import datetime, timezone
from typing import List

from ..exception import InvalidCheckerConfig, InvalidCheckerModule
from ..policyrep import SELinuxPolicy

from .checkermodule import CHECKER_REGISTRY, CheckerModule
from .globalkeys import CHECK_TYPE_KEY


SECTION_SEPARATOR = "---------------------------------------------------------\n\n"


class PolicyChecker:

    """Configuration file-driven automated policy analysis checks."""

    def __init__(self, policy: SELinuxPolicy, configpath: str) -> None:
        assert CHECKER_REGISTRY, "No checks are loaded, this is a bug."

        self.log = logging.getLogger(__name__)
        self.policy = policy
        self.checks: List[CheckerModule] = []
        self.config = configpath

    @property
    def config(self):
        return self._configpath

    @config.setter
    def config(self, configpath: str):
        self.log.info("Opening policy checker config {}.".format(configpath))
        try:
            with open(configpath, "r") as fd:
                config = configparser.ConfigParser()
                config.read_file(fd, source=configpath)
        except Exception as e:
            raise InvalidCheckerConfig("Unable to parse checker config {}: {}".format(
                configpath, e)) from e

        self.log.info("Validating configuration settings.")

        checks = []
        for checkname, checkconfig in config.items():
            if checkname == "DEFAULT":
                # top level/DEFAULT section is not a check.
                continue

            try:
                check_type = checkconfig[CHECK_TYPE_KEY]
            except KeyError as e:
                raise InvalidCheckerModule("{}: Missing {} option.".
                                           format(checkname, CHECK_TYPE_KEY))

            try:
                newcheck = CHECKER_REGISTRY[check_type](self.policy, checkname, checkconfig)
            except KeyError as e:
                raise InvalidCheckerModule("{}: Unknown policy check type: {}".
                                           format(checkname, check_type)) from e

            checks.append(newcheck)

        if not checks:
            raise InvalidCheckerConfig("No checks found in {}.".format(configpath))

        self.log.debug("Validated {} checks.".format(len(self.checks)))
        self.log.info("Successfully opened policy checker config {}.".format(configpath))
        self._configpath = configpath
        self.checks = checks
        self._config = config

    def run(self, output=sys.stdout) -> int:
        """Run all configured checks and print report to the file-like output."""
        failures = 0

        assert self.checks, "Configuration loaded but no checks configured. This is a bug."

        output.write(SECTION_SEPARATOR)
        output.write("Policy check configuration: {}\n".format(self.config))
        output.write("Policy being checked: {}\n".format(self.policy))
        output.write("Start time: {}\n\n".format(datetime.now(timezone.utc)))

        result_summary = []
        for check in self.checks:

            check_failures = 0
            try:
                output.write(SECTION_SEPARATOR)
                output.write("Check name: {}\n\n".format(check.checkname))
                if check.desc:
                    output.write("Description: {}\n\n".format(check.desc))

                if check.disable:
                    output.write("Check DISABLED.  Reason: {}\n\n".format(check.disable))
                    result_summary.append((check.checkname, "DISABLED ({})".format(check.disable)))
                    self.log.debug("Skipping disabled check {!r}: {}".format(check.checkname,
                                   check.disable))
                    continue

                self.log.debug("Running check {0!r}, type {1}.".format(
                    check.checkname, check.check_type))
                check.output = output
                check_failures += len(check.run())
                output.write("\n")
            except Exception as e:
                output.write("Unexpected error: {}.  Failing check.\n\n".format(e))
                self.log.debug("Exception info", exc_info=e)
                check_failures += 1

            if check_failures:
                output.write("Check FAILED\n\n")
                result_summary.append((check.checkname, "FAILED ({} failures)".format(
                    check_failures)))
            else:
                output.write("Check PASSED\n\n")
                result_summary.append((check.checkname, "PASSED"))

            failures += check_failures

        output.write(SECTION_SEPARATOR)
        output.write("Result Summary:\n\n")
        for checkname, result in result_summary:
            output.write("{:<39} {}\n".format(checkname, result))

        output.write("\n{} failure(s) found.\n\n".format(failures))
        output.write("Policy check configuration: {}\n".format(self.config))
        output.write("Policy being checked: {}\n".format(self.policy))
        output.write("End time: {}\n".format(datetime.now(timezone.utc)))
        self.log.info("{} failures found in {} checks.".format(failures, len(self.checks)))
        return failures
