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

from . import compquery
from .policyrep.objclass import NoCommon


class ObjClassQuery(compquery.ComponentQuery):

    """Query object classes."""

    def __init__(self, policy,
                 name="", name_regex=False,
                 common="", common_regex=False,
                 perms=set(), perms_equal=False, perms_regex=False,
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

        self.policy = policy
        self.set_name(name, regex=name_regex)
        self.set_common(common, regex=common_regex)
        self.set_perms(perms,
                       regex=perms_regex,
                       equal=perms_equal,
                       indirect=perms_indirect)

    def results(self):
        """Generator which yields all matching object classes."""

        for class_ in self.policy.classes():
            if self.name and not self._match_regex(
                    class_,
                    self.name,
                    self.name_regex,
                    self.name_cmp):
                continue

            if self.common:
                try:
                    if not self._match_regex(
                            class_.common,
                            self.common,
                            self.common_regex,
                            self.common_cmp):
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
                        self.perms_regex,
                        self.perms_cmp):
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

        self.common = str(common)

        for k in opts.keys():
            if k == "regex":
                self.common_regex = opts[k]
            else:
                raise NameError("Invalid common option: {0}".format(k))

        if self.common_regex:
            self.common_cmp = re.compile(self.common)
        else:
            self.common_cmp = None

    def set_perms(self, perms, **opts):
        """
        Set the criteria for the common's permissions.

        Parameter:
        perms 		Name to match the common's permissions.

        Keyword Options:
        regex       If true, regular expression matching will be used.
        equal		If true, the permisison set of the common
                    must equal the permissions criteria to
                    match. If false, any intersection in the
                    critera will cause a match.
        indirect    If true, the permissions inherited from a common
                    permission set will be included.

        Exceptions:
        NameError   Invalid keyword option.
        """

        self.perms = perms

        for k in opts.keys():
            if k == "regex":
                self.perms_regex = opts[k]
            elif k == "equal":
                self.perms_equal = opts[k]
            elif k == "indirect":
                self.perms_indirect = opts[k]
            else:
                raise NameError("Invalid permissions option: {0}".format(k))

        if self.perms_regex:
            self.perms_cmp = re.compile(self.perms)
        else:
            self.perms_cmp = None
