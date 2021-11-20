# Copyright 2014, 2016 Tresys Technology, LLC
# Copyright 2016-2018, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: LGPL-2.1-only
#

#
# Typing and enums
#
AnyDefault = Union[Default, DefaultRange]


class DefaultRuletype(PolicyEnum):

    """Enumeration of default rule types."""

    default_user = 1
    default_role = 2
    default_type = 3
    default_range = 4


class DefaultValue(PolicyEnum):

    """Enumeration of default values."""

    source = sepol.DEFAULT_SOURCE
    target = sepol.DEFAULT_TARGET
    glblub = sepol.DEFAULT_GLBLUB

    @classmethod
    def from_default_range(cls, range_):
        default_map = {sepol.DEFAULT_SOURCE_LOW: sepol.DEFAULT_SOURCE,
                       sepol.DEFAULT_SOURCE_HIGH: sepol.DEFAULT_SOURCE,
                       sepol.DEFAULT_SOURCE_LOW_HIGH: sepol.DEFAULT_SOURCE,
                       sepol.DEFAULT_TARGET_LOW: sepol.DEFAULT_TARGET,
                       sepol.DEFAULT_TARGET_HIGH: sepol.DEFAULT_TARGET,
                       sepol.DEFAULT_TARGET_LOW_HIGH: sepol.DEFAULT_TARGET,
                       sepol.DEFAULT_GLBLUB: sepol.DEFAULT_GLBLUB}

        try:
            return cls(default_map[range_])
        except KeyError as e:
            raise LowLevelPolicyError("Unsupported default value: {}".format(e)) from e


class DefaultRangeValue(PolicyEnum):

    """Enumeration of default range values."""

    low = 1
    high = 2
    low_high = 3

    @classmethod
    def from_default_range(cls, range_):
        default_map = {sepol.DEFAULT_SOURCE_LOW: 1,
                       sepol.DEFAULT_SOURCE_HIGH: 2,
                       sepol.DEFAULT_SOURCE_LOW_HIGH: 3,
                       sepol.DEFAULT_TARGET_LOW: 1,
                       sepol.DEFAULT_TARGET_HIGH: 2,
                       sepol.DEFAULT_TARGET_LOW_HIGH: 3,
                       sepol.DEFAULT_GLBLUB: None}

        try:
            value = default_map[range_]
            return None if value is None else cls(value)
        except KeyError as e:
            raise LowLevelPolicyError("Unsupported default_range value: {}".format(e)) from e


#
# Classes
#
cdef class Default(PolicyObject):

    """Base class for default_* statements."""

    cdef:
        readonly object ruletype
        readonly ObjClass tclass
        object _default

    # the default object is not exposed as a Python
    # attribute, as it collides with CPython code

    @staticmethod
    cdef inline Default factory(SELinuxPolicy policy, ObjClass tclass, user, role, type_, range_):
        """Factory function for Default objects."""
        cdef:
            Default obj
            DefaultRange objr

        if user:
            obj = Default()
            obj.policy = policy
            obj.tclass = tclass
            obj.ruletype = DefaultRuletype.default_user
            obj._default = DefaultValue(user)
            return obj

        if role:
            obj = Default()
            obj.policy = policy
            obj.tclass = tclass
            obj.ruletype = DefaultRuletype.default_role
            obj._default = DefaultValue(role)
            return obj

        if type_:
            obj = Default()
            obj.policy = policy
            obj.tclass = tclass
            obj.ruletype = DefaultRuletype.default_type
            obj._default = DefaultValue(type_)
            return obj

        if range_:
            objr = DefaultRange()
            objr.policy = policy
            objr.ruletype = DefaultRuletype.default_range
            objr.tclass = tclass
            objr._default = DefaultValue.from_default_range(range_)
            objr.default_range = DefaultRangeValue.from_default_range(range_)
            return objr

        raise ValueError("At least one of user, role, type_, or range_ must be specified.")

    def __eq__(self, other):
        return self.ruletype == other.ruletype \
                and self.tclass == other.tclass \
                and self.default == other.default

    def __hash__(self):
        return hash("{0.ruletype}|{0.tclass}".format(self))

    def __lt__(self, other):
        # this is used by Python sorting functions
        return str(self) < str(other)

    @property
    def default(self):
        return self._default

    def statement(self):
        return "{0.ruletype} {0.tclass} {0.default};".format(self)


cdef class DefaultRange(Default):

    """A default_range statement."""

    cdef readonly object default_range

    def __eq__(self, other):
        return self.ruletype == other.ruletype \
                and self.tclass == other.tclass \
                and self.default == other.default \
                and self.default_range == other.default_range

    def __hash__(self):
        return hash("{0.ruletype}|{0.tclass}".format(self))

    def __lt__(self, other):
        # this is used by Python sorting functions
        return str(self) < str(other)

    def statement(self):
        if self.default_range:
            return "{0.ruletype} {0.tclass} {0.default} {0.default_range};".format(self)
        else:
            return "{0.ruletype} {0.tclass} {0.default};".format(self)
