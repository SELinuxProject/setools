# Copyright 2014, Tresys Technology, LLC
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

from sepolgen import objectmodel as om

from . import policyrep

# build off of sepolgen perm map implementation


class PermissionMap(object, om.PermMappings):

    """Permission Map for information flow analysis."""

    def __init__(self, permmapfile="/usr/share/setools/perm_map"):
        """
        Parameter:
        permmapfile     The path to the permission map to load.
        """

        om.PermMappings.__init__(self)
        with open(permmapfile, "r") as fd:
            self.from_file(fd)

    def rule_weight(self, rule):
        """
        Get the type enforcement rule's information flow read and write weights.

        Parameter:
        rule            A type enforcement rule.

        Return: Tuple(read_weight, write_weight)
        read_weight     The type enforcement rule's read weight.
        write_weight    The type enforcement rule's write weight.
        """

        write_weight = 0
        read_weight = 0

        # iterate over the permissions and determine the
        # weight of the rule in each direction. The result
        # is the largest-weight permission in each direction
        for perm in rule.perms:
            mapping = self.get(str(rule.tclass), perm)

            if mapping.dir & om.FLOW_READ:
                read_weight = max(read_weight, mapping.weight)

            if mapping.dir & om.FLOW_WRITE:
                write_weight = max(write_weight, mapping.weight)

        return (read_weight, write_weight)
