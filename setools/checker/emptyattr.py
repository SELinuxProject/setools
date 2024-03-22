# Copyright 2020, Microsoft Corporation
#
# SPDX-License-Identifier: LGPL-2.1-only
#

import typing

from .. import exception, policyrep
from .checkermodule import CheckerModule
from .util import config_bool_value

ATTR_OPT: typing.Final[str] = "attr"
MISSINOK_OPT: typing.Final[str] = "missing_ok"

__all__: typing.Final[tuple[str, ...]] = ("EmptyTypeAttr",)


class EmptyTypeAttr(CheckerModule):

    """Checker module for asserting a type attribute is empty."""

    check_type = "empty_typeattr"
    check_config = frozenset((ATTR_OPT, MISSINOK_OPT))

    def __init__(self, policy: policyrep.SELinuxPolicy, checkname: str,
                 config: dict[str, str]) -> None:

        super().__init__(policy, checkname, config)
        self._attr: policyrep.TypeAttribute | str = ""
        self._missing_ok = False

        # this will make the check pass automatically
        # since the attribute is missing.  Only set if
        # missing_ok is True AND attr is missing.
        self._pass_by_missing = False

        self.missing_ok = config.get(MISSINOK_OPT)
        self.attr = config.get(ATTR_OPT, "")

    @property
    def attr(self) -> policyrep.TypeAttribute | str:
        return self._attr

    @attr.setter
    def attr(self, value: str | None) -> None:
        if not value:
            raise exception.InvalidCheckValue(
                f"{self.checkname}: \"{ATTR_OPT}\" setting is missing.")

        try:
            self._attr = self.policy.lookup_typeattr(value)
            self._pass_by_missing = False

        except exception.InvalidType as e:
            if not self.missing_ok:
                raise exception.InvalidCheckValue(
                    f"{self.checkname}: attr setting error: {e}") from e

            self._attr = value
            self._pass_by_missing = True

    @property
    def missing_ok(self):
        return self._missing_ok

    @missing_ok.setter
    def missing_ok(self, value) -> None:
        self._missing_ok = config_bool_value(value)

        if self._missing_ok and isinstance(self.attr, str):
            # attr is only a string if it doesn't exist.
            self._pass_by_missing = True
        else:
            self._pass_by_missing = False

    def run(self) -> list[policyrep.Type]:
        self.log.info(f"Checking type attribute {self.attr} is empty.")

        failures = list[policyrep.Type]()

        if self._pass_by_missing:
            self.log_info(f"    {self.attr} does not exist.")
        else:
            assert isinstance(self.attr, policyrep.TypeAttribute), \
                "attr should be a TypeAttribute object.  This is an SETools bug."

            self.output.write(f"Member types of {self.attr}:\n")

            types = sorted(self.attr.expand())
            if types:
                for type_ in types:
                    self.log_fail(type_.name)
                    failures.append(type_)
            else:
                self.log_ok("    <empty>")

        self.log.debug(f"{failures} failure(s)")
        return failures
