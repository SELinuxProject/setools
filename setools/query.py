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
import re


class PolicyQuery(object):

    """Abstract base class for SELinux policy queries."""

    @staticmethod
    def _match_regex(obj, criteria, regex, recomp):
        """
        Match the object with optional regular expression.

        Parameters:
        obj         The object to match.
        criteria    The criteria to match.
        regex       If regular expression matching should be used.
        recomp      The compiled regular expression.
        """

        if regex:
            return bool(recomp.search(str(obj)))
        else:
            return (obj == criteria)

    @staticmethod
    def _match_set(obj, criteria, equal):
        """
        Match the object (a set) with optional set equality.

        Parameters:
        obj         The object to match. (a set)
        criteria    The criteria to match. (a set)
        equal       If set equality should be used. Otherwise
                    any set intersection will match.
        """

        if equal:
            return (obj == criteria)
        else:
            return bool(obj.intersection(criteria))

    @staticmethod
    def _match_in_set(obj, criteria, regex, recomp):
        """
        Match if the criteria is in the list, with optional
        regular expression matching.

        Parameters:
        obj         The object to match.
        criteria    The criteria to match.
        regex       If regular expression matching should be used.
        recomp      The compiled regular expression.
        """

        if regex:
            return bool(list(filter(recomp.search, (str(m) for m in obj))))
        else:
            return (criteria in obj)

    @staticmethod
    def _match_regex_or_set(obj, criteria, equal, regex, recomp):
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
        recomp      The compiled regular expression.
        """

        if regex:
            return bool(list(filter(recomp.search, (str(m) for m in obj))))
        else:
            return PolicyQuery._match_set(obj, set(criteria), equal)

    def results(self):
        """
        Generator which returns the matches for the query.  This method
        should be overridden by subclasses.
        """
        raise NotImplementedError
