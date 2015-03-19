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
import re

from . import compquery
from . import contextquery


class FSUseQuery(contextquery.ContextQuery):

    """Query fs_use_* statements."""

    def __init__(self, policy,
                 ruletype=None,
                 fs=None, fs_regex=False,
                 user=None, user_regex=False,
                 role=None, role_regex=False,
                 type_=None, type_regex=False,
                 range_=None, range_overlap=False, range_subset=False,
                 range_superset=False, range_proper=False):
        """
        Parameters:
        policy          The policy to query.

        ruletype        The rule type(s) to match.
        fs              The criteria to match the file system type.
        fs_regex        If true, regular expression matching
                        will be used on the file system type.
        user            The criteria to match the context's user.
        user_regex      If true, regular expression matching
                        will be used on the user.
        role            The criteria to match the context's role.
        role_regex      If true, regular expression matching
                        will be used on the role.
        type_           The criteria to match the context's type.
        type_regex      If true, regular expression matching
                        will be used on the type.
        range_          The criteria to match the context's range.
        range_subset    If true, the criteria will match if it is a subset
                        of the context's range.
        range_overlap   If true, the criteria will match if it overlaps
                        any of the context's range.
        range_superset  If true, the criteria will match if it is a superset
                        of the context's range.
        range_proper    If true, use proper superset/subset operations.
                        No effect if not using set operations.
        """

        self.policy = policy

        self.set_ruletype(ruletype)
        self.set_fs(fs, regex=fs_regex)
        self.set_user(user, regex=user_regex)
        self.set_role(role, regex=role_regex)
        self.set_type(type_, regex=type_regex)
        self.set_range(range_, overlap=range_overlap, subset=range_subset,
                       superset=range_superset, proper=range_proper)

    def results(self):
        """Generator which yields all matching fs_use_* statements."""

        for fsu in self.policy.fs_uses():
            if self.ruletype and fsu.ruletype not in self.ruletype:
                continue

            if self.fs and not self._match_regex(
                    fsu.fs,
                    self.fs_cmp,
                    self.fs_regex):
                continue

            if not self._match_context(
                    fsu.context,
                    self.user_cmp,
                    self.user_regex,
                    self.role_cmp,
                    self.role_regex,
                    self.type_cmp,
                    self.type_regex,
                    self.range_cmp,
                    self.range_subset,
                    self.range_overlap,
                    self.range_superset,
                    self.range_proper):
                continue

            yield fsu

    def set_ruletype(self, ruletype):
        """
        Set the rule types for the rule query.

        Parameter:
        ruletype    The rule types to match.
        """

        self.ruletype = ruletype

    def set_fs(self, fs, **opts):
        """
        Set the criteria for matching the file system type.

        Parameter:
        fs         Name to match the file system.
        regex      If true, regular expression matching will be used.

        Exceptions:
        NameError  Invalid keyword option.
        """

        self.fs = fs

        for k in list(opts.keys()):
            if k == "regex":
                self.fs_regex = opts[k]
            else:
                raise NameError("Invalid name option: {0}".format(k))

        if not self.fs:
            self.fs_cmp = None
        elif self.fs_regex:
            self.fs_cmp = re.compile(self.fs)
        else:
            self.fs_cmp = self.fs
