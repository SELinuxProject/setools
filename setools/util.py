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

from .exception import InvalidPermission, NoCommon


def match_regex(obj, criteria, regex):
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


def match_set(obj, criteria, equal):
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


def match_in_set(obj, criteria, regex):
    """
    Match if the criteria is in the list, with optional
    regular expression matching.

    Parameters:
    obj         The object to match.
    criteria    The criteria to match.
    regex       If regular expression matching should be used.
    """

    if regex:
        return [m for m in obj if criteria.search(str(m))]
    else:
        return criteria in obj


def match_indirect_regex(obj, criteria, indirect, regex):
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
            return [o for o in obj.expand() if criteria.search(str(o))]
        else:
            return set(criteria.expand()).intersection(obj.expand())
    else:
        return match_regex(obj, criteria, regex)


def match_regex_or_set(obj, criteria, equal, regex):
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
        return [m for m in obj if criteria.search(str(m))]
    else:
        return match_set(obj, set(criteria), equal)


def match_range(obj, criteria, subset, overlap, superset, proper):
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


def match_level(obj, criteria, dom, domby, incomp):
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


def validate_perms_any(perms, tclass=None, policy=None):
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

    if not tclass and not policy:
        raise ValueError("No object class(es) or policy specified.")

    if tclass:
        # make local mutable set
        tclass = set(c for c in tclass)
    else:
        tclass = set(policy.classes())

    invalid = set(p for p in perms)
    for c in tclass:
        invalid -= c.perms

        with suppress(NoCommon):
            invalid -= c.common.perms

        if not invalid:
            break
    else:
        raise InvalidPermission("Invalid permissions: {}".format(", ".join(invalid)))
