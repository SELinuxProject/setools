# Copyright 2020, Microsoft Corporation
#
# SPDX-License-Identifier: LGPL-2.1-only
#

import sys
import configparser
import logging
from datetime import datetime, timezone
import typing

from ..exception import InvalidCheckerConfig, InvalidCheckerModule
from ..policyrep import SELinuxPolicy

from .checkermodule import CHECKER_REGISTRY, CheckerModule
from .globalkeys import CHECK_TYPE_KEY


SECTION_SEP: typing.Final[str] = "---------------------------------------------------------\n\n"


class PolicyChecker:

    """Configuration file-driven automated policy analysis checks."""

    def __init__(self, policy: SELinuxPolicy, configpath: str) -> None:
        assert CHECKER_REGISTRY, "No checks are loaded, this is a bug."

        self.log = logging.getLogger(__name__)
        self.policy = policy
        self.checks: list[CheckerModule] = []
        self.config = configpath

    @property
    def config(self) -> str:
        return self._configpath

    @config.setter
    def config(self, configpath: str) -> None:
        self.log.info(f"Opening policy checker config {configpath}.")
        try:
            with open(configpath, "r", encoding="utf-8") as fd:
                config = configparser.ConfigParser()
                config.read_file(fd, source=configpath)
        except Exception as e:
            raise InvalidCheckerConfig(f"Unable to parse checker config {configpath}: {e}") from e

        self.log.info("Validating configuration settings.")

        checks = []
        for checkname, checkconfig in config.items():
            if checkname == configparser.DEFAULTSECT:
                # top level/DEFAULT section is not a check.
                continue

            try:
                check_type = checkconfig[CHECK_TYPE_KEY]
            except KeyError as e:
                raise InvalidCheckerModule(f"{checkname}: Missing {CHECK_TYPE_KEY} option.") from e

            try:
                newcheck = CHECKER_REGISTRY[check_type](self.policy, checkname, checkconfig)
            except KeyError as e:
                raise InvalidCheckerModule(
                    f"{checkname}: Unknown policy check type: {check_type}") from e

            checks.append(newcheck)

        if not checks:
            raise InvalidCheckerConfig(f"No checks found in {configpath}.")

        self.log.debug(f"Validated {len(self.checks)} checks.")
        self.log.info(f"Successfully opened policy checker config {configpath}.")
        self._configpath = configpath
        self.checks = checks
        self._config = config

    def run(self, output: typing.TextIO = sys.stdout) -> int:
        """Run all configured checks and print report to the file-like output."""
        failures = 0

        assert self.checks, "Configuration loaded but no checks configured. This is a bug."

        output.write(SECTION_SEP)
        output.write(f"Policy check configuration: {self.config}\n")
        output.write(f"Policy being checked: {self.policy}\n")
        output.write(f"Start time: {datetime.now(timezone.utc)}\n\n")

        result_summary = []
        for check in self.checks:

            check_failures = 0
            try:
                output.write(SECTION_SEP)
                output.write(f"Check name: {check.checkname}\n\n")
                if check.desc:
                    output.write(f"Description: {check.desc}\n\n")

                if check.disable:
                    output.write(f"Check DISABLED.  Reason: {check.disable}\n\n")
                    result_summary.append((check.checkname, f"DISABLED ({check.disable})"))
                    self.log.debug(f"Skipping disabled check {check.checkname}: {check.disable}")
                    continue

                self.log.debug(f"Running check {check.checkname}, type {check.check_type}.")
                check.output = output
                check_failures += len(check.run())
                output.write("\n")
            except Exception as e:
                output.write(f"Unexpected error: {e}.  Failing check.\n\n")
                self.log.debug("Exception info", exc_info=e)
                check_failures += 1

            if check_failures:
                output.write("Check FAILED\n\n")
                result_summary.append((check.checkname, f"FAILED ({check_failures} failures)"))
            else:
                output.write("Check PASSED\n\n")
                result_summary.append((check.checkname, "PASSED"))

            failures += check_failures

        output.write(SECTION_SEP)
        output.write("Result Summary:\n\n")
        for checkname, result in result_summary:
            output.write(f"{checkname:<39} {result}\n")

        output.write(f"\n{failures} failure(s) found.\n\n")
        output.write(f"Policy check configuration: {self.config}\n")
        output.write(f"Policy being checked: {self.policy}\n")
        output.write(f"End time: {datetime.now(timezone.utc)}\n")
        self.log.info(f"{failures} failures found in {len(self.checks)} checks.")
        return failures
