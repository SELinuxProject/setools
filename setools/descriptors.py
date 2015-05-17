# Copyright 2015, Tresys Technology, LLC
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
"""
SETools descriptors.

These classes override how a class's attributes are get/set/deleted.
This is how the @property decorator works.

See https://docs.python.org/3/howto/descriptor.html
for more details.
"""

import re
from collections import defaultdict
from weakref import WeakKeyDictionary

#
# Query criteria descriptors
#
# Implementation note: if the name_regex attribute value
# is changed the criteria must be reset.
#


class CriteriaDescriptor(object):

    """
    Single item criteria descriptor.

    Parameters:
    name_regex      The name of instance's regex setting attribute;
                    used as name_regex below.  If unset,
                    regular expressions will never be used.
    lookup_function The name of the SELinuxPolicy lookup function,
                    e.g. lookup_type or lookup_boolean.
    default_value   The default value of the criteria.  The default
                    is None.

    Read-only instance attribute use (obj parameter):
    policy          The instance of SELinuxPolicy
    name_regex      This attribute is read to determine if
                    the criteria should be looked up or
                    compiled into a regex.  If the attribute
                    does not exist, False is assumed.
    """

    def __init__(self, name_regex=None, lookup_function=None, default_value=None):
        assert name_regex or lookup_function, "A simple attribute should be used if there is " \
            "no regex nor lookup function."
        self.regex = name_regex
        self.default_value = default_value
        self.lookup_function = lookup_function

        # use weak references so instances can be
        # garbage collected, rather than unnecessarily
        # kept around due to this descriptor.
        self.instances = WeakKeyDictionary()

    def __get__(self, obj, objtype=None):
        if obj is None:
            return self

        return self.instances.setdefault(obj, self.default_value)

    def __set__(self, obj, value):
        if not value:
            self.instances[obj] = None
        elif self.regex and getattr(obj, self.regex, False):
            self.instances[obj] = re.compile(value)
        elif self.lookup_function:
            lookup = getattr(obj.policy, self.lookup_function)
            self.instances[obj] = lookup(value)
        else:
            self.instances[obj] = value


class CriteriaSetDescriptor(CriteriaDescriptor):

    """Descriptor for a set of criteria."""

    def __set__(self, obj, value):
        if not value:
            self.instances[obj] = None
        elif self.regex and getattr(obj, self.regex, False):
            self.instances[obj] = re.compile(value)
        elif self.lookup_function:
            lookup = getattr(obj.policy, self.lookup_function)
            self.instances[obj] = set(lookup(v) for v in value)
        else:
            self.instances[obj] = set(value)


class RuletypeDescriptor(object):

    """
    Descriptor for a list of rule types.

    Parameters:
    validator       The name of the SELinuxPolicy ruletype
                    validator function, e.g. validate_te_ruletype
    default_value   The default value of the criteria.  The default
                    is None.

    Read-only instance attribute use (obj parameter):
    policy          The instance of SELinuxPolicy
    """

    def __init__(self, validator):
        self.validator = validator

        # use weak references so instances can be
        # garbage collected, rather than unnecessarily
        # kept around due to this descriptor.
        self.instances = WeakKeyDictionary()

    def __get__(self, obj, objtype=None):
        if obj is None:
            return self

        return self.instances.setdefault(obj, None)

    def __set__(self, obj, value):
        if value:
            validate = getattr(obj.policy, self.validator)
            validate(value)
            self.instances[obj] = value
        else:
            self.instances[obj] = None


#
# NetworkX Graph Descriptors
#
# These descriptors are used to simplify all
# of the dictionary use in the NetworkX graph.
#


class NetworkXGraphEdgeDescriptor(object):

    """
    Descriptor base class for NetworkX graph edge attributes.

    Parameter:
    name        The edge property name

    Instance class attribute use (obj parameter):
    G           The NetworkX graph
    source      The edge's source node
    target      The edge's target node
    """

    def __init__(self, propname):
        self.name = propname

    def __get__(self, obj, objtype=None):
        if obj is None:
            return self

        return obj.G[obj.source][obj.target][self.name]

    def __set__(self, obj, value):
        raise NotImplementedError

    def __delete__(self, obj):
        raise NotImplementedError


class EdgeAttrDict(NetworkXGraphEdgeDescriptor):

    """A descriptor for edge attributes that are dictionaries."""

    def __set__(self, obj, value):
        # None is a special value to initialize the attribute
        if value is None:
            obj.G[obj.source][obj.target][self.name] = defaultdict(list)
        else:
            raise ValueError("{0} dictionaries should not be assigned directly".format(self.name))

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


class EdgeAttrList(NetworkXGraphEdgeDescriptor):

    """A descriptor for edge attributes that are lists."""

    def __set__(self, obj, value):
        # None is a special value to initialize
        if value is None:
            obj.G[obj.source][obj.target][self.name] = []
        else:
            raise ValueError("{0} lists should not be assigned directly".format(self.name))

    def __delete__(self, obj):
        # in Python3 a .clear() function was added for lists
        # keep this implementation for Python 2 compat
        del obj.G[obj.source][obj.target][self.name][:]
