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
from . import contextquery


class GenfsconQuery(contextquery.ContextQuery):

    """Query genfscon statements."""

    def __init__(self, policy,
                 fs="", fs_regex=False,
                 path="", path_regex=False,
                 filetype=0,
                 user="", user_regex=False,
                 role="", role_regex=False,
                 type_="", type_regex=False,
                 range_="", range_overlap=False, range_subset=False,
                 range_superset=False, range_proper=False):
        """
        Parameters:
        policy          The policy to query.

        fs              The criteria to match the file system type.
        fs_regex        If true, regular expression matching
                        will be used on the file system type.
        path            The criteria to match the path.
        path_regex      If true, regular expression matching
                        will be used on the path.
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

        self.set_fs(fs, regex=fs_regex)
        self.set_path(path, regex=path_regex)
        self.set_filetype(filetype)
        self.set_user(user, regex=user_regex)
        self.set_role(role, regex=role_regex)
        self.set_type(type_, regex=type_regex)
        self.set_range(range_, overlap=range_overlap, subset=range_subset,
                       superset=range_superset, proper=range_proper)

    def results(self):
        """Generator which yields all matching genfscons."""

        for g in self.policy.genfscons():
            if self.fs and not self._match_regex(
                    g.fs,
                    self.fs,
                    self.fs_regex,
                    self.fs_cmp):
                continue

            if self.path and not self._match_regex(
                    g.path,
                    self.path,
                    self.path_regex,
                    self.path_cmp):
                continue

            if self.filetype and not self.filetype == g.filetype:
                continue

            if not self._match_context(
                    g.context,
                    self.user,
                    self.user_regex,
                    self.user_cmp,
                    self.role,
                    self.role_regex,
                    self.role_cmp,
                    self.type_,
                    self.type_regex,
                    self.type_cmp,
                    self.range_,
                    self.range_subset,
                    self.range_overlap,
                    self.range_superset,
                    self.range_proper):
                continue

            yield g

    def set_fs(self, fs, **opts):
        """
        Set the criteria for matching the file system type.

        Parameter:
        fs         Name to match the file system.
        regex      If true, regular expression matching will be used.

        Exceptions:
        NameError  Invalid keyword option.
        """

        self.fs = str(fs)

        for k in list(opts.keys()):
            if k == "regex":
                self.fs_regex = opts[k]
            else:
                raise NameError("Invalid name option: {0}".format(k))

        if self.fs_regex:
            self.fs_cmp = re.compile(self.fs)
        else:
            self.fs_cmp = None

    def set_filetype(self, filetype):
        """
        Set the criteria for matching the file type.

        Parameter:
        filetype    File type to match (e.g. stat.S_IFBLK or stat.S_IFREG).
        """

        self.filetype = filetype

    def set_path(self, path, **opts):
        """
        Set the criteria for matching the path.

        Parameter:
        path       Criteria to match the path.
        regex      If true, regular expression matching will be used.

        Exceptions:
        NameError  Invalid keyword option.
        """

        self.path = str(path)

        for k in list(opts.keys()):
            if k == "regex":
                self.path_regex = opts[k]
            else:
                raise NameError("Invalid name option: {0}".format(k))

        if self.path_regex:
            self.path_cmp = re.compile(self.path)
        else:
            self.path_cmp = None
