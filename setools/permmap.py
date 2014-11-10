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
from collections import defaultdict

from . import policyrep


class UnmappedPermission(Exception):

    """Exception for permissions that are unmapped"""
    pass


class PermissionMap(object):

    """Permission Map for information flow analysis."""

    valid_infoflow_directions = ["r", "w", "b", "n", "u"]
    min_weight = 1
    max_weight = 10

    def __init__(self, permmapfile="/usr/share/setools/perm_map"):
        """
        Parameter:
        permmapfile     The path to the permission map to load.
        """
        self.load(permmapfile)

    def load(self, permmapfile):
        """
        Parameter:
        permmapfile     The path to the permission map to load.
        """

        # state machine
        # 1 = read number of classes
        # 2 = read class name and number of perms
        # 3 = read perms
        with open(permmapfile, "r") as fd:
            class_count = 0
            num_classes = 0
            state = 1

            self.permmap = defaultdict(lambda: defaultdict(lambda: ('u', 1)))

            for line_num, line in enumerate(fd, start=1):
                entry = line.split()

                if class_count > num_classes:
                    break

                if len(entry) == 0 or entry[0][0] == '#':
                    continue

                if state == 1:
                    try:
                        num_classes = int(entry[0])
                    except ValueError:
                        raise SyntaxError("{0}:{1}:Invalid number of classes: {2}".format(
                            permmapfile, line_num, entry[0]))

                    if num_classes < 1:
                        SyntaxError("{0}:{1}:Number of classes must be positive: {2}".format(
                            permmapfile, line_num, entry[2]))

                    state = 2

                elif state == 2:
                    if len(entry) != 3 or entry[0] != "class":
                        raise SyntaxError(
                            "{0}:{1}:Invalid class declaration: {2}".format(permmapfile, line_num, entry))

                    class_name = str(entry[1])

                    try:
                        num_perms = int(entry[2])
                    except ValueError:
                        raise SyntaxError("{0}:{1}:Invalid number of permissions: {2}".format(
                            permmapfile, line_num, entry[2]))

                    if num_perms < 1:
                        SyntaxError("{0}:{1}:Number of permissions must be positive: {2}".format(
                            permmapfile, line_num, entry[2]))

                    class_count += 1
                    perm_count = 0
                    state = 3

                elif state == 3:
                    perm_name = entry[0]

                    flow_direction = str(entry[1])
                    if flow_direction not in self.valid_infoflow_directions:
                        raise SyntaxError("{0}:{1}:Invalid information flow direction: {2}".format(
                            permmapfile, line_num, entry[1]))

                    try:
                        weight = int(entry[2])
                    except ValueError:
                        SyntaxError("{0}:{1}:Invalid information flow weight: {2}".format(
                            permmapfile, line_num, entry[2]))

                    if not self.min_weight <= weight <= self.max_weight:
                        SyntaxError(
                            "{0}:{1}:Information flow weight must be 1-10: {2}".format(permmapfile, line_num, entry[2]))

                    self.permmap[class_name][perm_name] = (
                        flow_direction, weight)

                    perm_count += 1
                    if perm_count >= num_perms:
                        state = 2

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
        class_name = str(rule.tclass)

        # iterate over the permissions and determine the
        # weight of the rule in each direction. The result
        # is the largest-weight permission in each direction
        for perm_name in rule.perms:
            mapping = self.permmap[class_name][perm_name]

            if mapping[0] == "r":
                read_weight = max(read_weight, mapping[1])
            elif mapping[0] == "w":
                write_weight = max(write_weight, mapping[1])
            elif mapping[0] == "b":
                read_weight = max(read_weight, mapping[1])
                write_weight = max(write_weight, mapping[1])

        return (read_weight, write_weight)
