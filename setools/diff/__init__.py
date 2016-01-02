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
from .commons import CommonDifference
from .objclass import ObjClassDifference
from .roles import RolesDifference
from .types import TypesDifference

__all__ = ['PolicyDifference']


class PolicyDifference(CommonDifference,
                       ObjClassDifference,
                       RolesDifference,
                       TypesDifference):

    """
    Determine the differences from the left policy to the right policy.

    Parameters:
    left    A policy
    right   A policy
    """

    def _reset_diff(self):
        """Reset diff results on policy changes."""
        for c in PolicyDifference.__bases__:
            c._reset_diff(self)
