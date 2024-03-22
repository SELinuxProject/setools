# Copyright 2020, Microsoft Corporation
#
# SPDX-License-Identifier: LGPL-2.1-only
#

from collections import defaultdict
import typing

from .. import policyrep
from ..terulequery import TERuleQuery

from .checkermodule import CheckerModule
from .descriptors import ConfigSetDescriptor

EXEMPT_WRITE: typing.Final[str] = "exempt_write_domain"
EXEMPT_EXEC: typing.Final[str] = "exempt_exec_domain"
EXEMPT_FILE: typing.Final[str] = "exempt_file"

__all__: typing.Final[tuple[str, ...]] = ("ReadOnlyExecutables",)


class ReadOnlyExecutables(CheckerModule):

    """Checker module for asserting all executable files are read-only."""

    check_type = "ro_execs"
    check_config = frozenset((EXEMPT_WRITE, EXEMPT_EXEC, EXEMPT_FILE))

    exempt_write_domain = ConfigSetDescriptor[policyrep.Type](
        "lookup_type_or_attr", strict=False, expand=True)
    exempt_file = ConfigSetDescriptor[policyrep.Type](
        "lookup_type_or_attr", strict=False, expand=True)
    exempt_exec_domain = ConfigSetDescriptor[policyrep.Type](
        "lookup_type_or_attr", strict=False, expand=True)

    def __init__(self, policy: policyrep.SELinuxPolicy, checkname: str,
                 config: dict[str, str]) -> None:

        super().__init__(policy, checkname, config)
        self.exempt_write_domain = config.get(EXEMPT_WRITE)
        self.exempt_file = config.get(EXEMPT_FILE)
        self.exempt_exec_domain = config.get(EXEMPT_EXEC)

    def _collect_executables(self) -> defaultdict[policyrep.Type, set[policyrep.AVRule]]:
        self.log.debug("Collecting list of executable file types.")
        self.log.debug(f"{self.exempt_exec_domain=}")
        query = TERuleQuery(self.policy,
                            ruletype=("allow",),
                            tclass=("file",),
                            perms=("execute", "execute_no_trans"))

        collected = defaultdict[policyrep.Type, set[policyrep.AVRule]](set)
        for rule in query.results():
            sources = set(rule.source.expand()) - self.exempt_exec_domain
            targets = set(rule.target.expand()) - self.exempt_file

            # ignore rule if source or target is an empty attr
            if not sources or not targets:
                self.log.debug(f"Ignoring execute rule: {rule}")
                continue

            for t in targets:
                self.log.debug(f"Determined {t} is executable by: {rule}")
                assert isinstance(rule, policyrep.AVRule), \
                    f"Expected AVRule, got {type(rule)}, this is an SETools bug."
                collected[t].add(rule)

        return collected

    def run(self) -> list[policyrep.Type]:
        self.log.info("Checking executables are read-only.")

        query = TERuleQuery(self.policy,
                            ruletype=("allow",),
                            tclass=("file",),
                            perms=("write", "append"))
        executables = self._collect_executables()
        failures = defaultdict(set)

        for exec_type in executables.keys():
            self.log.debug(f"Checking if executable type {exec_type} is writable.")

            query.target = exec_type
            for rule in sorted(query.results()):
                if set(rule.source.expand()) - self.exempt_write_domain:
                    failures[exec_type].add(rule)

        for exec_type in sorted(failures.keys()):
            self.output.write("\n------------\n\n")
            self.output.write(f"Executable type {exec_type} is writable.\n\n")
            self.output.write("Execute rules:\n")
            for rule in sorted(executables[exec_type]):
                self.output.write(f"    * {rule}\n")

            self.output.write("\nWrite rules:\n")
            for rule in sorted(failures[exec_type]):
                self.log_fail(str(rule))

        self.log.debug(f"{len(failures)} failure(s)")
        return sorted(failures.keys())
