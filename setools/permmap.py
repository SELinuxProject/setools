# Copyright 2014-2015, Tresys Technology, LLC
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
import sys
import logging
from errno import ENOENT

from . import exception
from . import policyrep


class PermissionMap(object):

    """Permission Map for information flow analysis."""

    valid_infoflow_directions = ["r", "w", "b", "n", "u"]
    min_weight = 1
    max_weight = 10

    def __init__(self, permmapfile=None):
        """
        Parameter:
        permmapfile     The path to the permission map to load.
        """
        self.log = logging.getLogger(self.__class__.__name__)

        if permmapfile:
            self.load(permmapfile)
        else:
            for path in ["data/", sys.prefix + "/share/setools/"]:
                try:
                    self.load(path + "perm_map")
                    break
                except (IOError, OSError) as err:
                    if err.errno != ENOENT:
                        raise
            else:
                raise RuntimeError("Unable to load default permission map.")

    def load(self, permmapfile):
        """
        Parameter:
        permmapfile     The path to the permission map to load.
        """
        self.log.info("Opening permission map \"{0}\"".format(permmapfile))

        # state machine
        # 1 = read number of classes
        # 2 = read class name and number of perms
        # 3 = read perms
        with open(permmapfile, "r") as mapfile:
            class_count = 0
            num_classes = 0
            state = 1

            self.permmap = dict()

            for line_num, line in enumerate(mapfile, start=1):
                entry = line.split()

                if len(entry) == 0 or entry[0][0] == '#':
                    continue

                if state == 1:
                    try:
                        num_classes = int(entry[0])
                    except ValueError:
                        raise exception.PermissionMapParseError(
                            "{0}:{1}:Invalid number of classes: {2}".
                            format(permmapfile, line_num, entry[0]))

                    if num_classes < 1:
                        raise exception.PermissionMapParseError(
                            "{0}:{1}:Number of classes must be positive: {2}".
                            format(permmapfile, line_num, entry[0]))

                    state = 2

                elif state == 2:
                    if len(entry) != 3 or entry[0] != "class":
                        raise exception.PermissionMapParseError(
                            "{0}:{1}:Invalid class declaration: {2}".
                            format(permmapfile, line_num, entry))

                    class_name = str(entry[1])

                    try:
                        num_perms = int(entry[2])
                    except ValueError:
                        raise exception.PermissionMapParseError(
                            "{0}:{1}:Invalid number of permissions: {2}".
                            format(permmapfile, line_num, entry[2]))

                    if num_perms < 1:
                        raise exception.PermissionMapParseError(
                            "{0}:{1}:Number of permissions must be positive: {2}".
                            format(permmapfile, line_num, entry[2]))

                    class_count += 1
                    if class_count > num_classes:
                        raise exception.PermissionMapParseError(
                            "{0}:{1}:Extra class found: {2}".
                            format(permmapfile, line_num, class_name))

                    self.permmap[class_name] = dict()
                    perm_count = 0
                    state = 3

                elif state == 3:
                    perm_name = str(entry[0])

                    flow_direction = str(entry[1])
                    if flow_direction not in self.valid_infoflow_directions:
                        raise exception.PermissionMapParseError(
                            "{0}:{1}:Invalid information flow direction: {2}".
                            format(permmapfile, line_num, entry[1]))

                    try:
                        weight = int(entry[2])
                    except ValueError:
                        raise exception.PermissionMapParseError(
                            "{0}:{1}:Invalid permission weight: {2}".
                            format(permmapfile, line_num, entry[2]))

                    if not self.min_weight <= weight <= self.max_weight:
                        raise exception.PermissionMapParseError(
                            "{0}:{1}:Permission weight must be {3}-{4}: {2}".
                            format(permmapfile, line_num, entry[2],
                                   self.min_weight, self.max_weight))

                    self.permmap[class_name][perm_name] = {'direction': flow_direction,
                                                           'weight': weight,
                                                           'enabled': True}

                    perm_count += 1
                    if perm_count >= num_perms:
                        state = 2

    def exclude_class(self, class_):
        """
        Exclude all permissions in an object class for calculating rule weights.

        Parameter:
        class_              The object class to exclude.

        Exceptions:
        UnmappedClass       The specified object class is not mapped.
        """

        classname = str(class_)

        try:
            for perm in self.permmap[classname]:
                self.permmap[classname][perm]['enabled'] = False
        except KeyError:
            raise exception.UnmappedClass("{0} is not mapped.".format(classname))

    def exclude_permission(self, class_, permission):
        """
        Exclude a permission for calculating rule weights.

        Parameter:
        class_              The object class of the permission.
        permission          The permission name to exclude.

        Exceptions:
        UnmappedClass       The specified object class is not mapped.
        UnmappedPermission  The specified permission is not mapped for the object class.
        """
        classname = str(class_)

        if classname not in self.permmap:
            raise exception.UnmappedClass("{0} is not mapped.".format(classname))

        try:
            self.permmap[classname][permission]['enabled'] = False
        except KeyError:
            raise exception.UnmappedPermission("{0}:{1} is not mapped.".
                                               format(classname, permission))

    def include_class(self, class_):
        """
        Include all permissions in an object class for calculating rule weights.

        Parameter:
        class_              The object class to include.

        Exceptions:
        UnmappedClass       The specified object class is not mapped.
        """

        classname = str(class_)

        try:
            for perm in self.permmap[classname]:
                self.permmap[classname][perm]['enabled'] = True
        except KeyError:
            raise exception.UnmappedClass("{0} is not mapped.".format(classname))

    def include_permission(self, class_, permission):
        """
        Include a permission for calculating rule weights.

        Parameter:
        class_              The object class of the permission.
        permission          The permission name to include.

        Exceptions:
        UnmappedClass       The specified object class is not mapped.
        UnmappedPermission  The specified permission is not mapped for the object class.
        """

        classname = str(class_)

        if classname not in self.permmap:
            raise exception.UnmappedClass("{0} is not mapped.".format(classname))

        try:
            self.permmap[classname][permission]['enabled'] = True
        except KeyError:
            raise exception.UnmappedPermission("{0}:{1} is not mapped.".
                                               format(classname, permission))

    def map_policy(self, policy):
        """Create mappings for all classes and permissions in the specified policy."""
        for class_ in policy.classes():
            class_name = str(class_)

            if class_name not in self.permmap:
                self.log.info("Adding unmapped class {0} from {1}".format(class_name, policy))
                self.permmap[class_name] = dict()

            perms = class_.perms

            try:
                perms |= class_.common.perms
            except policyrep.exception.NoCommon:
                pass

            for perm_name in perms:
                if perm_name not in self.permmap[class_name]:
                    self.log.info("Adding unmapped permission {0} in {1} from {2}".
                                  format(perm_name, class_name, policy))
                    self.permmap[class_name][perm_name] = {'direction': 'u',
                                                           'weight': 1,
                                                           'enabled': True}

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

        if rule.ruletype != 'allow':
            raise exception.RuleTypeError("{0} rules cannot be used for calculating a weight".
                                          format(rule.ruletype))

        if class_name not in self.permmap:
            raise exception.UnmappedClass("{0} is not mapped.".format(class_name))

        # iterate over the permissions and determine the
        # weight of the rule in each direction. The result
        # is the largest-weight permission in each direction
        for perm_name in rule.perms:
            try:
                mapping = self.permmap[class_name][perm_name]
            except KeyError:
                raise exception.UnmappedPermission("{0}:{1} is not mapped.".
                                                   format(class_name, perm_name))

            if not mapping['enabled']:
                continue

            if mapping['direction'] == "r":
                read_weight = max(read_weight, mapping['weight'])
            elif mapping['direction'] == "w":
                write_weight = max(write_weight, mapping['weight'])
            elif mapping['direction'] == "b":
                read_weight = max(read_weight, mapping['weight'])
                write_weight = max(write_weight, mapping['weight'])

        return (read_weight, write_weight)

    def set_direction(self, class_, permission, direction):
        """
        Set the information flow direction of a permission.

        Parameter:
        class_              The object class of the permission.
        permission          The permission name.
        direction           The information flow direction the permission (r/w/b/n).

        Exceptions:
        UnmappedClass       The specified object class is not mapped.
        UnmappedPermission  The specified permission is not mapped for the object class.
        """

        if direction not in self.valid_infoflow_directions:
            raise ValueError("Invalid information flow direction: {0}".format(direction))

        classname = str(class_)

        if classname not in self.permmap:
            raise exception.UnmappedClass("{0} is not mapped.".format(classname))

        try:
            self.permmap[classname][permission]['direction'] = direction
        except KeyError:
            raise exception.UnmappedPermission("{0}:{1} is not mapped.".
                                               format(classname, permission))

    def set_weight(self, class_, permission, weight):
        """
        Set the weight of a permission.

        Parameter:
        class_              The object class of the permission.
        permission          The permission name.
        weight              The weight of the permission (1-10).

        Exceptions:
        UnmappedClass       The specified object class is not mapped.
        UnmappedPermission  The specified permission is not mapped for the object class.
        """

        if not self.min_weight <= weight <= self.max_weight:
            raise ValueError("Permission weights must be 1-10: {0}".format(weight))

        classname = str(class_)

        if classname not in self.permmap:
            raise exception.UnmappedClass("{0} is not mapped.".format(classname))

        try:
            self.permmap[classname][permission]['weight'] = weight
        except KeyError:
            raise exception.UnmappedPermission("{0}:{1} is not mapped.".
                                               format(classname, permission))
