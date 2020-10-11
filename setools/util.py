# Copyright 2016, Tresys Technology, LLC
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

from contextlib import suppress
from typing import Iterable, List, Optional, Tuple

from .exception import InvalidPermission, NoCommon
from .policyrep import Level, ObjClass, SELinuxPolicy


def match_regex(obj, criteria, regex: bool) -> bool:
    """
    Match the object with optional regular expression.

    Parameters:
    obj         The object to match.
    criteria    The criteria to match.
    regex       If regular expression matching should be used.
    """

    if regex:
        return bool(criteria.search(str(obj)))
    else:
        return obj == criteria


def match_set(obj, criteria, equal: bool) -> bool:
    """
    Match the object (a set) with optional set equality.

    Parameters:
    obj         The object to match. (a set)
    criteria    The criteria to match. (a set)
    equal       If set equality should be used. Otherwise
                any set intersection will match.
    """

    if equal:
        return obj == criteria
    else:
        return bool(obj.intersection(criteria))


def match_in_set(obj, criteria, regex: bool) -> bool:
    """
    Match if the criteria is in the list, with optional
    regular expression matching.

    Parameters:
    obj         The object to match.
    criteria    The criteria to match.
    regex       If regular expression matching should be used.
    """

    if regex:
        return bool([m for m in obj if criteria.search(str(m))])
    else:
        return criteria in obj


def match_indirect_regex(obj, criteria, indirect: bool, regex: bool) -> bool:
    """
    Match the object with optional regular expression and indirection.

    Parameters:
    obj         The object to match.
    criteria    The criteria to match.
    regex       If regular expression matching should be used.
    indirect    If object indirection should be used, e.g.
                expanding an attribute.
    """

    if indirect:
        if regex:
            return bool([o for o in obj.expand() if criteria.search(str(o))])
        else:
            return bool(set(criteria.expand()).intersection(obj.expand()))
    else:
        return match_regex(obj, criteria, regex)


def match_regex_or_set(obj, criteria, equal: bool, regex: bool) -> bool:
    """
    Match the object (a set) with either set comparisons
    (equality or intersection) or by regex matching of the
    set members.  Regular expression matching will override
    the set equality option.

    Parameters:
    obj         The object to match. (a set)
    criteria    The criteria to match.
    equal       If set equality should be used.  Otherwise
                any set intersection will match. Ignored
                if regular expression matching is used.
    regex       If regular expression matching should be used.
    """

    if regex:
        return bool([m for m in obj if criteria.search(str(m))])
    else:
        return match_set(obj, set(criteria), equal)


def match_range(obj, criteria, subset: bool, overlap: bool, superset: bool, proper: bool) -> bool:
    """
    Match ranges of objects.

    obj         An object with attributes named "low" and "high", representing the range.
    criteria    An object with attributes named "low" and "high", representing the criteria.
    subset      If true, the criteria will match if it is a subset obj's range.
    overlap     If true, the criteria will match if it overlaps any of the obj's range.
    superset    If true, the criteria will match if it is a superset of the obj's range.
    proper      If true, use proper superset/subset operations.
                No effect if not using set operations.
    """

    if overlap:
        return ((obj.low <= criteria.low <= obj.high) or (
            obj.low <= criteria.high <= obj.high) or (
            criteria.low <= obj.low and obj.high <= criteria.high))
    elif subset:
        if proper:
            return ((obj.low < criteria.low and criteria.high <= obj.high) or (
                obj.low <= criteria.low and criteria.high < obj.high))
        else:
            return obj.low <= criteria.low and criteria.high <= obj.high
    elif superset:
        if proper:
            return ((criteria.low < obj.low and obj.high <= criteria.high) or (
                criteria.low <= obj.low and obj.high < criteria.high))
        else:
            return (criteria.low <= obj.low and obj.high <= criteria.high)
    else:
        return criteria.low == obj.low and obj.high == criteria.high


def match_level(obj: Level, criteria: Level, dom: bool, domby: bool, incomp: bool) -> bool:
    """
    Match the an MLS level.

    obj         The level to match.
    criteria    The criteria to match. (a level)
    dom         If true, the criteria will match if it dominates obj.
    domby       If true, the criteria will match if it is dominated by obj.
    incomp      If true, the criteria will match if it is incomparable to obj.
    """

    if dom:
        return (criteria >= obj)
    elif domby:
        return (criteria <= obj)
    elif incomp:
        return (criteria ^ obj)
    else:
        return (criteria == obj)


def validate_perms_any(perms: Iterable[str], tclass: Optional[Iterable[ObjClass]] = None,
                       policy: Optional[SELinuxPolicy] = None) -> None:
    """
    Validate that each permission is valid for at least one
    of specified object classes.  If no classes are specified,
    then all classes in the policy are checked.

    A tclass or policy must be specified.

    Parameters:
    perms       A container of str permission names.

    Keyword Parameters.
    tclass      An iterable of 1 or more ObjClass.
    policy      A SELinuxPolicy

    Exceptions:
    ValueError          Invalid parameter.
    InvalidPermission   One or more permissions is invalid.

    Return:     None
    """

    if not perms:
        raise ValueError("No permissions specified.")

    if tclass:
        # make local mutable set
        selected_classes = set(c for c in tclass)
    elif policy:
        selected_classes = set(policy.classes())
    else:
        raise ValueError("No object class(es) or policy specified.")

    invalid = set(p for p in perms)
    for c in selected_classes:
        invalid -= c.perms

        with suppress(NoCommon):
            invalid -= c.common.perms

        if not invalid:
            break
    else:
        if tclass:
            raise InvalidPermission(
                "Permission(s) do not exist in the specified classes: {}"
                .format(", ".join(invalid)))
        else:
            raise InvalidPermission(
                "Permission(s) do not exist any class: {}"
                .format(", ".join(invalid)))


def xperm_str_to_tuple_ranges(perms: str, separator: str = ",") -> List[Tuple[int, int]]:
    """
    Create a extended permission list of ranges from a string representation of ranges.
    This does not do any checking for out-of-range values.

    Parameters:
    perms       A string representation of integer extended permissions, such as
                "0x08,0x30-0x40,0x55,0x60-0x65"

    Keyword Parameters:
    separator   The separator between permissions/permission ranges.
                Default is ","

    Return:     List[Tuple[int, int]] equivalent of the permissions.
    """

    xperms: List[Tuple[int, int]] = []
    for item in perms.split(separator):
        rng = item.split("-")
        if len(rng) == 2:
            xperms.append((int(rng[0], base=16), int(rng[1], base=16)))
        elif len(rng) == 1:
            xperms.append((int(rng[0], base=16), int(rng[0], base=16)))
        else:
            raise ValueError("Unable to parse \"{}\" for xperms.".format(item))

    return xperms
