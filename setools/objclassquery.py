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
from .policyrep.objclass import NoCommon


class ObjClassQuery(compquery.ComponentQuery):

    """Query object classes."""

    def __init__(self, policy,
                 name=None, name_regex=False,
                 common=None, common_regex=False,
                 perms=None, perms_equal=False, perms_regex=False,
                 perms_indirect=True):
        """
        Parameters:
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
        self.log = logging.getLogger(self.__class__.__name__)

        self.policy = policy
        self.set_name(name, regex=name_regex)
        self.set_common(common, regex=common_regex)
        self.set_perms(perms, regex=perms_regex, equal=perms_equal, indirect=perms_indirect)

    def results(self):
        """Generator which yields all matching object classes."""
        self.log.info("Generating results from {0.policy}".format(self))
        self.log.debug("Name: {0.name_cmp!r}, regex: {0.name_regex}".format(self))
        self.log.debug("Common: {0.common_cmp!r}, regex: {0.common_regex}".format(self))
        self.log.debug("Perms: {0.perms_cmp}, regex: {0.perms_regex}, "
                       "eq: {0.perms_equal}, indirect: {0.perms_indirect}".format(self))

        for class_ in self.policy.classes():
            if self.name and not self._match_name(class_):
                continue

            if self.common:
                try:
                    if not self._match_regex(
                            class_.common,
                            self.common_cmp,
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
                        self.perms_cmp,
                        self.perms_equal,
                        self.perms_regex):
                    continue

            yield class_

    def set_common(self, common, **opts):
        """
        Set the criteria for matching the common's name.

        Parameter:
        name       Name to match the common's name.
        regex      If true, regular expression matching will be used.

        Exceptions:
        NameError  Invalid keyword option.
        """

        self.common = common

        for k in list(opts.keys()):
            if k == "regex":
                self.common_regex = opts[k]
            else:
                raise NameError("Invalid common option: {0}".format(k))

        if not self.common:
            self.common_cmp = None
        elif self.common_regex:
            self.common_cmp = re.compile(self.common)
        else:
            self.common_cmp = self.policy.lookup_common(self.common)

    def set_perms(self, perms, **opts):
        """
        Set the criteria for the common's permissions.

        Parameter:
        perms       Name to match the common's permissions.

        Keyword Options:
        regex       If true, regular expression matching will be used.
        equal       If true, the permisison set of the common
                    must equal the permissions criteria to
                    match. If false, any intersection in the
                    critera will cause a match.
        indirect    If true, the permissions inherited from a common
                    permission set will be included.

        Exceptions:
        NameError   Invalid keyword option.
        """

        self.perms = perms

        for k in list(opts.keys()):
            if k == "regex":
                self.perms_regex = opts[k]
            elif k == "equal":
                self.perms_equal = opts[k]
            elif k == "indirect":
                self.perms_indirect = opts[k]
            else:
                raise NameError("Invalid permissions option: {0}".format(k))

        if not self.perms:
            self.perms_cmp = None
        elif self.perms_regex:
            self.perms_cmp = re.compile(self.perms)
        else:
            self.perms_cmp = self.perms
