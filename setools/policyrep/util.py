# Copyright 2016, Chris PeBenito <pebenito@ieee.org>
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
import warnings

from enum import Enum


class PolicyEnum(Enum):

    """
    Base class for policy enumerations.

    Standard Enum behavior except for returning
    the enum name for the default string representation
    and basic string format.
    """

    def __str__(self):
        return self.name

    def __format__(self, spec):
        if not spec:
            return self.name
        else:
            return super(PolicyEnum, self).__format__(spec)

    def __eq__(self, other):
        if isinstance(other, str):
            warnings.warn("{} has changed to an enumeration.  In the future, direct string "
                          "comparisons will be deprecated.".format(self.__class__.__name__),
                          PendingDeprecationWarning)
            return self.name == other
        else:
            return super(PolicyEnum, self).__eq__(other)

    def __hash__(self):
        return hash(self.name)

    @classmethod
    def lookup(cls, value):
        """Look up an enumeration by name or value."""

        try:
            return cls(value)
        except ValueError:
            return cls[value]
