# Copyright 2015, Tresys Technology, LLC
# Copyright 2016, 2018, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: LGPL-2.1-only
#
"""
SETools descriptors.

These classes override how a class's attributes are get/set/deleted.
This is how the @property decorator works.

See https://docs.python.org/3/howto/descriptor.html
for more details.
"""

import re
from abc import ABC, abstractmethod
from collections import defaultdict
from collections.abc import Callable, Collection
import typing

from . import policyrep, util

T = typing.TypeVar("T")

#
# Query criteria descriptors
#
# Implementation note: if the name_regex attribute value
# is changed the criteria must be reset.
#


class CriteriaDescriptor(typing.Generic[T]):

    """
    Single item criteria descriptor.

    Keyword Parameters:
    name_regex      The name of instance's regex setting attribute;
                    used as name_regex below.  If unset,
                    regular expressions will never be used.
    lookup_function The name of the SELinuxPolicy lookup function,
                    e.g. lookup_type or lookup_boolean.
    default_value   The default value of the criteria.  The default
                    is None.
    enum_class      The class of enumeration which supports a
                    lookup class method.

    Read-only instance attribute use (obj parameter):
    policy          The instance of SELinuxPolicy
    name_regex      This attribute is read to determine if
                    the criteria should be looked up or
                    compiled into a regex.  If the attribute
                    does not exist, False is assumed.
    """

    def __init__(self, name_regex: str | None = None,
                 lookup_function: Callable | str | None = None,
                 default_value=None, enum_class: type[policyrep.PolicyEnum] | None = None) -> None:

        assert name_regex or lookup_function or enum_class, \
            "A simple attribute should be used if there is no regex, lookup function, or enum."
        assert not (lookup_function and enum_class), \
            "Lookup functions and enum classes are mutually exclusive."
        self.regex: str | None = name_regex
        self.default_value = default_value
        self.lookup_function: Callable | str | None = lookup_function
        self.enum_class = enum_class
        self.name: str

    def __set_name__(self, owner, name: str) -> None:
        self.name = f"_internal_{name}"

    def __get__(self, obj, objtype=None) -> T:
        if obj is None:
            raise AttributeError

        return getattr(obj, self.name, self.default_value)

    def __set__(self, obj, value) -> None:
        if not value:
            setattr(obj, self.name, self.default_value)
        elif self.regex and getattr(obj, self.regex, False):
            setattr(obj, self.name, re.compile(value))
        elif self.lookup_function:
            if callable(self.lookup_function):
                lookup = self.lookup_function
            else:
                lookup = getattr(obj.policy, self.lookup_function)
            setattr(obj, self.name, lookup(value))
        elif self.enum_class:
            setattr(obj, self.name, self.enum_class.lookup(value))
        else:
            setattr(obj, self.name, value)


class CriteriaSetDescriptor(CriteriaDescriptor[set[T]]):

    """Descriptor for a set of criteria."""

    def __set__(self, obj, value):
        if not value:
            setattr(obj, self.name, self.default_value)
        elif self.regex and getattr(obj, self.regex, False):
            setattr(obj, self.name, re.compile(value))
        elif self.lookup_function:
            if callable(self.lookup_function):
                lookup = self.lookup_function
            else:
                lookup = getattr(obj.policy, self.lookup_function)
            setattr(obj, self.name, frozenset(lookup(v) for v in value))
        elif self.enum_class:
            setattr(obj, self.name, frozenset(self.enum_class.lookup(v) for v in value))
        else:
            setattr(obj, self.name, frozenset(value))


class CriteriaPermissionSetDescriptor(CriteriaDescriptor[set[str]]):

    """
    Descriptor for a set of permissions criteria.

    name_regex      The name of instance's regex setting attribute;
                    used as name_regex below.  If unset,
                    regular expressions will never be used.
    default_value   The default value of the criteria.  The default
                    is None.

    Read-only instance attribute use (obj parameter):
    policy          The instance of SELinuxPolicy
    tclass          If it exists, it will be used to validate the
                    permissions.  See validate_perms_any()
    tclass_regex    If tclass is a regex, the above permission validation
                    will not use tclass: permissions are verified to be in
                    at least one class in the policy but not verified that the
                    permissions are in classes that the regex matches.  Assumes False
                    if the attribute doesn't exist.
    """

    def __init__(self, name_regex: str | None = None, default_value=None) -> None:
        self.regex = name_regex
        self.default_value = default_value

    def __set__(self, obj, value) -> None:
        if not value:
            setattr(obj, self.name, self.default_value)
        elif self.regex and getattr(obj, self.regex, False):
            setattr(obj, self.name, re.compile(value))
        else:
            perms = frozenset(v for v in value)

            if getattr(obj, "tclass_regex", False):
                tclass = None
            else:
                tclass = getattr(obj, "tclass", None)

            if tclass and not isinstance(tclass, Collection):
                tclass = frozenset((tclass,))

            util.validate_perms_any(perms,
                                    tclass=tclass,
                                    policy=obj.policy)

            setattr(obj, self.name, perms)


#
# NetworkX Graph Descriptors
#
# These descriptors are used to simplify all
# of the dictionary use in the NetworkX graph.
#


class NetworkXGraphEdgeDescriptor(ABC):

    """
    Descriptor abstract base class for NetworkX graph edge attributes.

    Keyword Parameter:
    name        Override the graph edge property name.

    Instance class attribute use (obj parameter):
    G           The NetworkX graph
    source      The edge's source node
    target      The edge's target node
    """

    def __init__(self, propname: str | None = None) -> None:
        self.override_name = propname
        self.name: str

    def __set_name__(self, owner, name):
        self.name = self.override_name if self.override_name else name

    def __get__(self, obj, objtype=None):
        if obj is None:
            return self

        try:
            return obj.G[obj.source][obj.target][self.name]
        except KeyError:
            raise AttributeError(self.name)

    @abstractmethod
    def __set__(self, obj, value):
        pass

    @abstractmethod
    def __delete__(self, obj):
        pass


class EdgeAttrDict(NetworkXGraphEdgeDescriptor):

    """A descriptor for edge attributes that are dictionaries."""

    def __set__(self, obj, value):
        # None is a special value to initialize the attribute
        if value is None:
            obj.G[obj.source][obj.target][self.name] = defaultdict(list)
        else:
            raise AttributeError(f"{self.name} dictionaries should not be assigned directly")

    def __delete__(self, obj):
        obj.G[obj.source][obj.target][self.name].clear()


class EdgeAttrIntMax(NetworkXGraphEdgeDescriptor):

    """
    A descriptor for edge attributes that are non-negative integers that always
    keep the max assigned value until re-initialized.
    """

    def __set__(self, obj, value):
        # None is a special value to initialize
        if value is None:
            obj.G[obj.source][obj.target][self.name] = 0
        else:
            current_value = obj.G[obj.source][obj.target][self.name]
            obj.G[obj.source][obj.target][self.name] = max(current_value, value)

    def __delete__(self, obj):
        obj.G[obj.source][obj.target][self.name] = 0


class EdgeAttrList(NetworkXGraphEdgeDescriptor):

    """A descriptor for edge attributes that are lists."""

    def __set__(self, obj, value):
        # None is a special value to initialize
        if value is None:
            obj.G[obj.source][obj.target][self.name] = []
        else:
            raise ValueError(f"{self.name} lists should not be assigned directly")

    def __delete__(self, obj):
        obj.G[obj.source][obj.target][self.name].clear()


#
# Permission map descriptors
#
class PermissionMapDescriptor:

    """
    Descriptor for Permission Map mappings.

    Parameter:
    validator   A callable for validating the setting.

    Instance class attribute use (obj parameter):
    _perm_map   The full permission map.
    class_      The mapping's object class
    perm        The mapping's permission
    """

    def __init__(self, validator: Callable):
        self.validator: Callable = validator
        self.name: str

    def __set_name__(self, owner, name):
        self.name = name

    def __get__(self, obj, objtype=None):
        if obj is None:
            return self

        return obj._perm_map[obj.class_][obj.perm][self.name]

    def __set__(self, obj, value):
        obj._perm_map[obj.class_][obj.perm][self.name] = self.validator(value)

    def __delete__(self, obj):
        raise AttributeError
