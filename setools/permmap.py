# Copyright 2014-2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
import logging
import copy
from collections import OrderedDict
from contextlib import suppress
from dataclasses import dataclass
from importlib import resources as pkg_resources
import pathlib
from typing import cast, Dict, Final, Iterable, Union

from . import exception
from .descriptors import PermissionMapDescriptor
from .mixins import TupleCompat
from .policyrep import AVRule, SELinuxPolicy, TERuletype

# This is the filename in the Python package
DEFAULT_PERM_MAP: Final[str] = "perm_map"

INFOFLOW_DIRECTIONS: Final = ("r", "w", "b", "n", "u")
MIN_WEIGHT: Final[int] = 1
MAX_WEIGHT: Final[int] = 10


@dataclass
class RuleWeight(TupleCompat):

    """The read and write weights for a rule, given all of its permissions."""

    read: int
    write: int


#
# Settings validation functions for Mapping descriptors
#
def validate_weight(weight: int) -> int:
    if not MIN_WEIGHT <= weight <= MAX_WEIGHT:
        raise ValueError("Permission weights must be 1-10: {0}".format(weight))

    return weight


def validate_direction(direction: str) -> str:
    if direction not in INFOFLOW_DIRECTIONS:
        raise ValueError("Invalid information flow direction: {0}".format(direction))

    return direction


# Internal data structure for permission map
MapStruct = Dict[str, Dict[str, Dict[str, Union[bool, str, int]]]]


class Mapping:

    """A mapping for a permission in the permission map."""

    weight = PermissionMapDescriptor(validate_weight)
    direction = PermissionMapDescriptor(validate_direction)
    enabled = PermissionMapDescriptor(bool)
    class_: str
    perm: str

    def __init__(self, perm_map: MapStruct, classname: str, permission: str,
                 create: bool = False) -> None:

        self._perm_map = perm_map
        self.class_ = classname
        self.perm = permission

        if create:
            if classname not in self._perm_map:
                self._perm_map[classname] = OrderedDict()

            self._perm_map[classname][permission] = {'direction': 'u',
                                                     'weight': 1,
                                                     'enabled': True}

        else:
            if classname not in self._perm_map:
                raise exception.UnmappedClass("{0} is not mapped.".format(classname))

            if permission not in self._perm_map[classname]:
                raise exception.UnmappedPermission("{0}:{1} is not mapped.".
                                                   format(classname, permission))

    def __lt__(self, other) -> bool:
        if self.class_ == other.class_:
            return self.perm < other.perm

        return self.class_ < other.class_


class PermissionMap:

    """Permission Map for information flow analysis."""

    MIN_WEIGHT: Final[int] = MIN_WEIGHT
    MAX_WEIGHT: Final[int] = MAX_WEIGHT

    def __init__(self, permmapfile: str | pathlib.Path | None = None) -> None:
        """
        Parameter:
        permmapfile     The path to the permission map to load.
        """
        self.log = logging.getLogger(__name__)
        self._permmap: MapStruct = OrderedDict()
        self._permmapfile: pathlib.Path

        if permmapfile:
            self.load(permmapfile)
        else:
            package_location = pkg_resources.files("setools")
            with pkg_resources.as_file(package_location / DEFAULT_PERM_MAP) as path:
                self.load(path)

    def __str__(self) -> str:
        return str(self._permmapfile)

    def __deepcopy__(self, memo) -> 'PermissionMap':
        newobj = PermissionMap.__new__(PermissionMap)
        newobj.log = self.log
        newobj._permmap = copy.deepcopy(self._permmap)
        newobj._permmapfile = self._permmapfile
        memo[id(self)] = newobj
        return newobj

    def __iter__(self) -> Iterable[Mapping]:
        for cls in self.classes():
            for mapping in self.perms(cls):
                yield mapping

    def load(self, permmapfile: str | pathlib.Path) -> None:
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
            total_perms = 0
            class_count = 0
            num_classes = 0
            state = 1

            self._permmap.clear()

            for line_num, line in enumerate(mapfile, start=1):
                entry = line.split()

                if len(entry) == 0 or entry[0][0] == '#':
                    continue

                if state == 1:
                    try:
                        num_classes = int(entry[0])
                    except ValueError as ex:
                        raise exception.PermissionMapParseError(
                            "{0}:{1}:Invalid number of classes: {2}".
                            format(permmapfile, line_num, entry[0])) from ex

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
                    except ValueError as ex:
                        raise exception.PermissionMapParseError(
                            "{0}:{1}:Invalid number of permissions: {2}".
                            format(permmapfile, line_num, entry[2])) from ex

                    if num_perms < 1:
                        raise exception.PermissionMapParseError(
                            "{0}:{1}:Number of permissions must be positive: {2}".
                            format(permmapfile, line_num, entry[2]))

                    class_count += 1
                    if class_count > num_classes:
                        raise exception.PermissionMapParseError(
                            "{0}:{1}:Extra class found: {2}".
                            format(permmapfile, line_num, class_name))

                    self._permmap[class_name] = OrderedDict()
                    perm_count = 0
                    state = 3

                elif state == 3:
                    perm_name = str(entry[0])

                    flow_direction = str(entry[1])
                    if flow_direction not in INFOFLOW_DIRECTIONS:
                        raise exception.PermissionMapParseError(
                            "{0}:{1}:Invalid information flow direction: {2}".
                            format(permmapfile, line_num, entry[1]))

                    try:
                        weight = int(entry[2])
                    except ValueError as ex:
                        raise exception.PermissionMapParseError(
                            "{0}:{1}:Invalid permission weight: {2}".
                            format(permmapfile, line_num, entry[2])) from ex

                    if not MIN_WEIGHT <= weight <= MAX_WEIGHT:
                        raise exception.PermissionMapParseError(
                            "{0}:{1}:Permission weight must be {3}-{4}: {2}".
                            format(permmapfile, line_num, entry[2],
                                   MIN_WEIGHT, MAX_WEIGHT))

                    self.log.debug("Read {0}:{1} {2} {3}".format(
                                   class_name, perm_name, flow_direction, weight))

                    if flow_direction == 'u':
                        self.log.info("Permission {0}:{1} is unmapped.".format(
                                      class_name, perm_name))

                    mapping = Mapping(self._permmap, class_name, perm_name, create=True)
                    mapping.direction = flow_direction
                    mapping.weight = weight

                    total_perms += 1
                    perm_count += 1
                    if perm_count >= num_perms:
                        state = 2

        self._permmapfile = pathlib.Path(permmapfile)
        self.log.info("Successfully opened permission map \"{0}\"".format(permmapfile))
        self.log.debug("Read {0} classes and {1} total permissions.".format(
                       class_count, total_perms))

    def save(self, permmapfile: str) -> None:
        """
        Save the permission map to the specified path.  Existing files
        will be overwritten.

        Parameter:
        permmapfile         The path to write the permission map.
        """
        with open(permmapfile, "w") as mapfile:
            self.log.info("Writing permission map to \"{0}\"".format(permmapfile))
            mapfile.write("{0}\n\n".format(len(self._permmap)))

            for classname, perms in self._permmap.items():
                mapfile.write("class {0} {1}\n".format(classname, len(perms)))

                for permname, settings in perms.items():
                    direction = cast(str, settings['direction'])
                    weight = cast(int, settings['weight'])

                    assert MIN_WEIGHT <= weight <= MAX_WEIGHT, \
                        "{0}:{1} weight is out of range ({2}). This is an SETools bug.".format(
                            classname, permname, weight)

                    assert direction in INFOFLOW_DIRECTIONS, \
                        "{0}:{1} flow direction ({2}) is invalid. This is an SETools bug.".format(
                            classname, permname, direction)

                    if direction == 'u':
                        self.log.warning("Warning: permission {0} in class {1} is unmapped.".format(
                                         permname, classname))

                    mapfile.write("{0:>20} {1:>9} {2:>9}\n".format(permname, direction, weight))

                mapfile.write("\n")

            self.log.info("Successfully wrote permission map to \"{0}\"".format(permmapfile))

    def classes(self) -> Iterable[str]:
        """
        Generate class names in the permission map.

        Yield:
        class       An object class name.
        """
        yield from self._permmap.keys()

    def perms(self, class_: str) -> Iterable[Mapping]:
        """
        Generate permission mappings for the specified class.

        Parameter:
        class_      An object class name.

        Yield:
        Mapping     A permission's complete map (weight, direction, enabled)
        """
        try:
            for perm in self._permmap[class_].keys():
                yield Mapping(self._permmap, class_, perm)
        except KeyError as ex:
            raise exception.UnmappedClass("{0} is not mapped.".format(class_)) from ex

    def mapping(self, class_: str, perm: str) -> Mapping:
        """Retrieve a specific permission's mapping."""
        return Mapping(self._permmap, class_, perm)

    def exclude_class(self, class_: str) -> None:
        """
        Exclude all permissions in an object class for calculating rule weights.

        Parameter:
        class_              The object class to exclude.

        Exceptions:
        UnmappedClass       The specified object class is not mapped.
        """
        for perm in self.perms(class_):
            perm.enabled = False

    def exclude_permission(self, class_: str, permission: str) -> None:
        """
        Exclude a permission for calculating rule weights.

        Parameter:
        class_              The object class of the permission.
        permission          The permission name to exclude.

        Exceptions:
        UnmappedClass       The specified object class is not mapped.
        UnmappedPermission  The specified permission is not mapped for the object class.
        """
        Mapping(self._permmap, class_, permission).enabled = False

    def include_class(self, class_: str) -> None:
        """
        Include all permissions in an object class for calculating rule weights.

        Parameter:
        class_              The object class to include.

        Exceptions:
        UnmappedClass       The specified object class is not mapped.
        """

        for perm in self.perms(class_):
            perm.enabled = True

    def include_permission(self, class_: str, permission: str) -> None:
        """
        Include a permission for calculating rule weights.

        Parameter:
        class_              The object class of the permission.
        permission          The permission name to include.

        Exceptions:
        UnmappedClass       The specified object class is not mapped.
        UnmappedPermission  The specified permission is not mapped for the object class.
        """

        Mapping(self._permmap, class_, permission).enabled = True

    def map_policy(self, policy: SELinuxPolicy) -> None:
        """Create mappings for all classes and permissions in the specified policy."""
        for class_ in policy.classes():
            class_name = str(class_)

            if class_name not in self._permmap:
                self.log.debug("Adding unmapped class {0} from {1}".format(class_name, policy))
                self._permmap[class_name] = OrderedDict()

            perms = class_.perms

            with suppress(exception.NoCommon):
                perms |= class_.common.perms

            for perm_name in perms:
                if perm_name not in self._permmap[class_name]:
                    self.log.debug("Adding unmapped permission {0} in {1} from {2}".
                                   format(perm_name, class_name, policy))
                    Mapping(self._permmap, class_name, perm_name, create=True)

    def rule_weight(self, rule: AVRule) -> RuleWeight:
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

        if rule.ruletype != TERuletype.allow:
            raise exception.RuleTypeError("{0} rules cannot be used for calculating a weight".
                                          format(rule.ruletype))

        # iterate over the permissions and determine the
        # weight of the rule in each direction. The result
        # is the largest-weight permission in each direction
        for perm_name in rule.perms:
            mapping = Mapping(self._permmap, class_name, perm_name)

            if not mapping.enabled:
                continue

            if mapping.direction == "r":
                read_weight = max(read_weight, mapping.weight)
            elif mapping.direction == "w":
                write_weight = max(write_weight, mapping.weight)
            elif mapping.direction == "b":
                read_weight = max(read_weight, mapping.weight)
                write_weight = max(write_weight, mapping.weight)

        return RuleWeight(read_weight, write_weight)

    def set_direction(self, class_: str, permission: str, direction: str) -> None:
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
        Mapping(self._permmap, class_, permission).direction = direction

    def set_weight(self, class_: str, permission: str, weight: int) -> None:
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
        Mapping(self._permmap, class_, permission).weight = weight
