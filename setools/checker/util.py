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

from ..exception import InvalidCheckValue, InvalidClass, InvalidPermission, InvalidType
from ..util import validate_perms_any


def config_list_to_class(policy, config):
    """
    Convert a comma separated string into a set of object classes.

    Parameters:
    policy      A SELinuxPolicy
    config      A str with a comma-separated set of object classes.

    Return:     Frozenset containing policy objects in the config.
    """
    if not config:
        return frozenset()

    try:
        tclass = frozenset(policy.lookup_class(c.strip()) for c in config.split(","))
    except InvalidClass as e:
        raise InvalidCheckValue("Invalid tclass setting: {}".format(e)) from e

    return tclass


def config_list_to_perms(policy, config, tclass=None):
    """
    Convert a comma separated string into a set of permissions.

    Parameters:
    policy      A SELinuxPolicy
    config      A str with a comma-separated set of permissions.

    Keyword Parameters:
    tclass      A container of ObjClass.  If specified, the perms must be valid
                for at least one of the classes.  If not specified, the permissions
                must be valid for at least one class in the entire policy.

    Return:     Frozenset containing permission strings.
    """
    if not config:
        return frozenset()

    try:
        perms = frozenset(p.strip() for p in config.split(","))
        validate_perms_any(perms, tclass=tclass, policy=policy)
    except InvalidPermission as e:
        raise InvalidCheckValue("Invalid perms setting: {}".format(e)) from e

    return perms


def config_to_type_or_attr(policy, config):
    """
    Convert an option into a type or type attribute.

    Parameters:
    policy      A SELinuxPolicy
    config      A str with a types/type attributes.

    Return:     A type or typeattribute object.
    """

    if not config:
        return None

    try:
        return policy.lookup_type_or_attr(config.strip())
    except InvalidType as e:
        raise InvalidCheckValue("Invalid type/attribute setting: {}".format(e))


def config_list_to_types_or_attrs(log, policy, config, strict=True, expand=False):
    """
    Convert a comma separated string into a set of types/type attributes.

    Parameters:
    log         A logging object.
    policy      A SELinuxPolicy
    config      A str with a comma-separated set of types/type attributes.

    Keyword Parameters:
    strict      Bool, if True policy lookup errors will be a configuration error.
                If False, only an INFO level warrning will be issued.
                Default is True.
    expand      Bool, if True, attributes will be expanded. Default is False.

    Return:     Frozenset containing policy objects in the config.
    """

    if not config:
        return frozenset()

    ret = set()
    for item in config.split(","):
        try:
            obj = policy.lookup_type_or_attr(item.strip())
            if expand:
                ret.update(obj.expand())
            else:
                ret.add(obj)
        except InvalidType as e:
            if strict:
                log.error("Invalid type/attribute: {}".format(e))
                log.debug("Traceback:", exc_info=e)
                raise InvalidCheckValue("Invalid type/attribute setting: {}".format(e)) from e

            log.info("Invalid type/attribute setting: {}".format(e))

    return frozenset(ret)
