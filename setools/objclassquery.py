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
import logging
import re

from . import compquery
from .descriptors import CriteriaDescriptor, CriteriaSetDescriptor
from .policyrep.exception import NoCommon


class ObjClassQuery(compquery.ComponentQuery):

    """
    Query object classes.

    Parameter:
    policy          The policy to query.

    Keyword Parameters/Class attributes:
    name            The name of the object set to match.
    name_regex      If true, regular expression matching will
                    be used for matching the name.
    common          The name of the inherited common to match.
    common_regex    If true, regular expression matching will
                    be used for matching the common name.
    perms           The permissions to match.
    perms_equal     If true, only commons with permission sets
                    that are equal to the criteria will
                    match.  Otherwise, any intersection
                    will match.
    perms_regex     If true, regular expression matching
                    will be used on the permission names instead
                    of set logic.
                    comparison will not be used.
    perms_indirect  If false, permissions inherited from a common
                    permission set not will be evaluated.  Default
                    is true.
    """

    common = CriteriaDescriptor("common_regex", "lookup_common")
    common_regex = False
    perms = CriteriaSetDescriptor("perms_regex")
    perms_equal = False
    perms_indirect = True
    perms_regex = False

    def results(self):
        """Generator which yields all matching object classes."""
        self.log.info("Generating results from {0.policy}".format(self))
        self.log.debug("Name: {0.name!r}, regex: {0.name_regex}".format(self))
        self.log.debug("Common: {0.common!r}, regex: {0.common_regex}".format(self))
        self.log.debug("Perms: {0.perms}, regex: {0.perms_regex}, "
                       "eq: {0.perms_equal}, indirect: {0.perms_indirect}".format(self))

        for class_ in self.policy.classes():
            if not self._match_name(class_):
                continue

            if self.common:
                try:
                    if not self._match_regex(
                            class_.common,
                            self.common,
                            self.common_regex):
                        continue
                except NoCommon:
                    continue

            if self.perms:
                perms = class_.perms

                if self.perms_indirect:
                    try:
                        perms |= class_.common.perms
                    except NoCommon:
                        pass

                if not self._match_regex_or_set(
                        perms,
                        self.perms,
                        self.perms_equal,
                        self.perms_regex):
                    continue

            yield class_
