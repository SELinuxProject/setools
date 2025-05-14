# Copyright 2020, 2025, Microsoft Corporation
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
EXEMPT_LOAD: typing.Final[str] = "exempt_load_domain"
EXEMPT_FILE: typing.Final[str] = "exempt_file"

__all__: typing.Final[tuple[str, ...]] = ("ReadOnlyKernelModules",)


class ReadOnlyKernelModules(CheckerModule):

    """Checker module for asserting all kernel modules are read-only."""

    check_type = "ro_kmods"
    check_config = frozenset((EXEMPT_WRITE, EXEMPT_LOAD, EXEMPT_FILE))

    exempt_write_domain = ConfigSetDescriptor[policyrep.Type](
        "lookup_type_or_attr", strict=False, expand=True)
    exempt_file = ConfigSetDescriptor[policyrep.Type](
        "lookup_type_or_attr", strict=False, expand=True)
    exempt_load_domain = ConfigSetDescriptor[policyrep.Type](
        "lookup_type_or_attr", strict=False, expand=True)

    def __init__(self, policy: policyrep.SELinuxPolicy, checkname: str,
                 config: dict[str, str]) -> None:

        super().__init__(policy, checkname, config)
        self.exempt_write_domain = config.get(EXEMPT_WRITE)
        self.exempt_file = config.get(EXEMPT_FILE)
        self.exempt_load_domain = config.get(EXEMPT_LOAD)

    def _collect_kernel_mods(self) -> defaultdict[policyrep.Type, set[policyrep.AVRule]]:
        self.log.debug("Collecting list of kernel module types.")
        self.log.debug(f"{self.exempt_load_domain=}")
        query = TERuleQuery(self.policy,
                            ruletype=("allow",),
                            tclass=("system",),
                            perms=("module_load",))

        collected = defaultdict[policyrep.Type, set[policyrep.AVRule]](set)
        for rule in query.results():
            sources = set(rule.source.expand()) - self.exempt_load_domain
            targets = set(rule.target.expand()) - self.exempt_file

            # remove self rules
            targets -= sources

            # ignore rule if source or target is an empty attr
            if not sources or not targets:
                self.log.debug(f"Ignoring empty module_load rule: {rule}")
                continue

            for t in targets:
                self.log.debug(f"Determined {t} is a kernel module by: {rule}")
                assert isinstance(rule, policyrep.AVRule), \
                    f"Expected AVRule, got {type(rule)}, this is an SETools bug."
                collected[t].add(rule)

        return collected

    def run(self) -> list[policyrep.Type]:
        self.log.info("Checking kernel modules are read-only.")

        query = TERuleQuery(self.policy,
                            ruletype=("allow",),
                            tclass=("file",),
                            perms=("write", "append"))
        kmods = self._collect_kernel_mods()
        failures = defaultdict(set)

        for kmod_type in kmods.keys():
            self.log.debug(f"Checking if kernel module type {kmod_type} is writable.")

            query.target = kmod_type
            for rule in sorted(query.results()):
                if set(rule.source.expand()) - self.exempt_write_domain:
                    failures[kmod_type].add(rule)

        for kmod_type in sorted(failures.keys()):
            self.output.write("\n------------\n\n")
            self.output.write(f"Kernel module type {kmod_type} is writable.\n\n")
            self.output.write("Module load rules:\n")
            for rule in sorted(kmods[kmod_type]):
                self.output.write(f"    * {rule}\n")

            self.output.write("\nWrite rules:\n")
            for rule in sorted(failures[kmod_type]):
                self.log_fail(str(rule))

        self.log.debug(f"{len(failures)} failure(s)")
        return sorted(failures.keys())
