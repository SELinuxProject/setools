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
from collections import defaultdict
from typing import Dict, List, Set

from ..policyrep import AnyTERule, Type
from ..terulequery import TERuleQuery

from .checkermodule import CheckerModule
from .descriptors import ConfigSetDescriptor


EXEMPT_WRITE = "exempt_write_domain"
EXEMPT_EXEC = "exempt_exec_domain"
EXEMPT_FILE = "exempt_file"


class ReadOnlyExecutables(CheckerModule):

    """Checker module for asserting all executable files are read-only."""

    check_type = "ro_execs"
    check_config = frozenset((EXEMPT_WRITE, EXEMPT_EXEC, EXEMPT_FILE))

    exempt_write_domain = ConfigSetDescriptor("lookup_type_or_attr", strict=False, expand=True)
    exempt_file = ConfigSetDescriptor("lookup_type_or_attr", strict=False, expand=True)
    exempt_exec_domain = ConfigSetDescriptor("lookup_type_or_attr", strict=False, expand=True)

    def __init__(self, policy, checkname, config) -> None:
        super().__init__(policy, checkname, config)
        self.log = logging.getLogger(__name__)

        self.exempt_write_domain = config.get(EXEMPT_WRITE)
        self.exempt_file = config.get(EXEMPT_FILE)
        self.exempt_exec_domain = config.get(EXEMPT_EXEC)

    def _collect_executables(self) -> Dict[Type, Set[AnyTERule]]:
        self.log.debug("Collecting list of executable file types.")
        self.log.debug("Ignore exec domains: {!r}".format(self.exempt_exec_domain))
        query = TERuleQuery(self.policy,
                            ruletype=("allow",),
                            tclass=("file",),
                            perms=("execute", "execute_no_trans"))

        collected = defaultdict(set)
        for rule in query.results():
            sources = set(rule.source.expand()) - self.exempt_exec_domain
            targets = set(rule.target.expand()) - self.exempt_file

            # ignore rule if source or target is an empty attr
            if not sources or not targets:
                self.log.debug("Ignoring execute rule: {}".format(rule))
                continue

            for t in targets:
                self.log.debug("Determined {} is executable by: {}".format(t, rule))
                collected[t].add(rule)

        return collected

    def run(self) -> List:
        self.log.info("Checking executables are read-only.")

        query = TERuleQuery(self.policy,
                            ruletype=("allow",),
                            tclass=("file",),
                            perms=("write", "append"))
        executables = self._collect_executables()
        failures = defaultdict(set)

        for exec_type in executables.keys():
            self.log.debug("Checking if executable type {} is writable.".format(exec_type))

            query.target = exec_type
            for rule in sorted(query.results()):
                if set(rule.source.expand()) - self.exempt_write_domain:
                    failures[exec_type].add(rule)

        for exec_type in sorted(failures.keys()):
            self.output.write("\n------------\n\n")
            self.output.write("Executable type {} is writable.\n\n".format(exec_type))
            self.output.write("Execute rules:\n")
            for rule in sorted(executables[exec_type]):
                self.output.write("    * {}\n".format(rule))

            self.output.write("\nWrite rules:\n")
            for rule in sorted(failures[exec_type]):
                self.log_fail(str(rule))

        self.log.debug("{} failure(s)".format(len(failures)))
        return sorted(failures.keys())
