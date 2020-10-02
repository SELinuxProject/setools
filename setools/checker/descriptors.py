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
from typing import Callable, Union

from ..exception import InvalidCheckValue
from ..descriptors import CriteriaDescriptor, CriteriaPermissionSetDescriptor


class ConfigDescriptor(CriteriaDescriptor):

    """
    Single item configuration option descriptor.

    Parameter:
    lookup_function The name of the SELinuxPolicy lookup function,
                    e.g. lookup_type or lookup_boolean.

    Read-only instance attribute use (obj parameter):
    checkname       The name of the check.
    policy          The instance of SELinuxPolicy
    """

    def __init__(self, lookup_function: Union[Callable, str]) -> None:
        super().__init__(lookup_function=lookup_function)

    def __set__(self, obj, value):
        if not value:
            self.instances[obj] = None
        else:
            try:
                super().__set__(obj, value.strip())
            except ValueError as ex:
                raise InvalidCheckValue("{}: Invalid {} setting: {}".format(
                    obj.checkname, self.name, ex)) from ex


class ConfigSetDescriptor(CriteriaDescriptor):

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

    def __init__(self, lookup_function: Union[Callable, str], strict: bool = True,
                 expand: bool = False) -> None:

        super().__init__(lookup_function=lookup_function, default_value=frozenset())
        self.strict = strict
        self.expand = expand

    def __set__(self, obj, value):
        if not value:
            self.instances[obj] = frozenset()
        else:
            log = obj.log
            if callable(self.lookup_function):
                lookup = self.lookup_function
            else:
                lookup = getattr(obj.policy, self.lookup_function)
            ret = set()
            for item in (i for i in value.split(" ") if i):
                try:
                    o = lookup(item)
                    if self.expand:
                        ret.update(o.expand())
                    else:
                        ret.add(o)
                except ValueError as e:
                    if self.strict:
                        log.error("Invalid {} item: {}".format(self.name, e))
                        log.debug("Traceback:", exc_info=e)
                        raise InvalidCheckValue("{}: Invalid {} item: {}".format(
                            obj.checkname, self.name, e)) from e

                    log.info("{}: Invalid {} item: {}".format(
                        obj.checkname, self.name, e))

            self.instances[obj] = frozenset(ret)


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

    def __set__(self, obj, value):
        if not value:
            self.instances[obj] = frozenset()
        else:
            try:
                super().__set__(obj, (v for v in value.split(" ") if v))
            except ValueError as ex:
                raise InvalidCheckValue("{}: Invalid {} setting: {}".format(
                    obj.checkname, self.name, ex)) from ex
