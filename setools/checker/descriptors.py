# Copyright 2020, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: LGPL-2.1-only
#
import re
import typing

from ..exception import InvalidCheckValue
from ..descriptors import (CriteriaDescriptor, CriteriaSetDescriptor,
                           CriteriaPermissionSetDescriptor)

T = typing.TypeVar("T")

if typing.TYPE_CHECKING:
    from collections.abc import Callable
    from .checkermodule import CheckerModule


class ConfigDescriptor(CriteriaDescriptor[T]):

    """
    Single item configuration option descriptor.

    Parameter:
    lookup_function The name of the SELinuxPolicy lookup function,
                    e.g. lookup_type or lookup_boolean.

    Read-only instance attribute use (obj parameter):
    checkname       The name of the check.
    policy          The instance of SELinuxPolicy
    """

    def __init__(self, lookup_function: "Callable | str") -> None:
        super().__init__(lookup_function=lookup_function)

    def __set__(self, obj: "CheckerModule", value: str | None) -> None:
        if not value:
            setattr(obj, self.name, None)
        else:
            try:
                super().__set__(obj, value.strip())
            except ValueError as ex:
                raise InvalidCheckValue(
                    f"{obj.checkname}: Invalid {self.name} setting: {ex}") from ex


class ConfigSetDescriptor(CriteriaSetDescriptor[T]):

    """
    Descriptor for a configuration option set.

    Parameter:
    lookup_function The name of the SELinuxPolicy lookup function,
                    e.g. lookup_type or lookup_boolean.

    Keyword Parameters:
    strict          (Bool) If True, all objects must exist in the policy
                    when setting the value.  If False, any objects that
                    fail the policy lookup will be dropped instead of raising
                    an exception.  The default is True.
    expand          (Bool) If True, each object will be expanded.  Default
                    is False.

    Read-only instance attribute use (obj parameter):
    checkname       The name of the check.
    log             A logger instance.
    policy          The instance of SELinuxPolicy
    """

    def __init__(self, lookup_function: "Callable | str", strict: bool = True,
                 expand: bool = False) -> None:

        super().__init__(lookup_function=lookup_function, default_value=frozenset[T]())
        self.strict = strict
        self.expand = expand

    def __set__(self, obj: "CheckerModule", value: str | None) -> None:
        if not value:
            setattr(obj, self.name, frozenset[T]())
        else:
            log = obj.log
            lookup: "Callable[[str], T]"
            if callable(self.lookup_function):
                lookup = self.lookup_function
            else:
                assert self.lookup_function, "lookup_function not set, this is an SETools bug"
                lookup = getattr(obj.policy, self.lookup_function)
            ret: set[T] = set()
            for item in (i for i in re.split(r"\s", value) if i):
                try:
                    o: T = lookup(item)
                    if self.expand:
                        assert hasattr(o, "expand"), \
                            f"{o} does not have expand method, this is an SETools bug."
                        ret.update(o.expand())
                    else:
                        ret.add(o)
                except ValueError as e:
                    if self.strict:
                        log.error(f"Invalid {self.name} item: {e}")
                        log.debug("Traceback:", exc_info=True)
                        raise InvalidCheckValue(
                            f"{obj.checkname}: Invalid {self.name} item: {e}") from e

                    log.info(f"{obj.checkname}: Invalid {self.name} item: {e}")

            setattr(obj, self.name, frozenset(ret))


class ConfigPermissionSetDescriptor(CriteriaPermissionSetDescriptor):

    """
    Descriptor for a configuration permissions set.

    Read-only instance attribute use (obj parameter):
    checkname       The name of the check.
    policy          The instance of SELinuxPolicy
    tclass          If it exists, it will be used to validate the
                    permissions.  See validate_perms_any()
    """

    def __init__(self) -> None:
        super().__init__(default_value=frozenset())

    def __set__(self, obj: "CheckerModule", value: str | None) -> None:
        if not value:
            setattr(obj, self.name, frozenset())
        else:
            try:
                super().__set__(obj, (v for v in value.split(" ") if v))
            except ValueError as ex:
                raise InvalidCheckValue(
                    f"{obj.checkname}: Invalid {self.name} setting: {ex}") from ex
