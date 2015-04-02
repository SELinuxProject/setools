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

from . import contextquery


class GenfsconQuery(contextquery.ContextQuery):

    """Query genfscon statements."""

    def __init__(self, policy,
                 fs=None, fs_regex=False,
                 path=None, path_regex=False,
                 filetype=None,
                 user=None, user_regex=False,
                 role=None, role_regex=False,
                 type_=None, type_regex=False,
                 range_=None, range_overlap=False, range_subset=False,
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
        self.log = logging.getLogger(self.__class__.__name__)

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
        self.log.info("Generating results from {0.policy}".format(self))
        self.log.debug("FS: {0.fs_cmp!r}, regex: {0.fs_regex}".format(self))
        self.log.debug("Path: {0.path_cmp!r}, regex: {0.path_regex}".format(self))
        self.log.debug("Filetype: {0.filetype!r}".format(self))
        self.log.debug("User: {0.user_cmp!r}, regex: {0.user_regex}".format(self))
        self.log.debug("Role: {0.role_cmp!r}, regex: {0.role_regex}".format(self))
        self.log.debug("Type: {0.type_cmp!r}, regex: {0.type_regex}".format(self))
        self.log.debug("Range: {0.range_!r}, subset: {0.range_subset}, overlap: {0.range_overlap}, "
                       "superset: {0.range_superset}, proper: {0.range_proper}".format(self))

        for g in self.policy.genfscons():
            if self.fs and not self._match_regex(
                    g.fs,
                    self.fs_cmp,
                    self.fs_regex):
                continue

            if self.path and not self._match_regex(
                    g.path,
                    self.path_cmp,
                    self.path_regex):
                continue

            if self.filetype and not self.filetype == g.filetype:
                continue

            if not self._match_context(
                    g.context,
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

        self.path = path

        for k in list(opts.keys()):
            if k == "regex":
                self.path_regex = opts[k]
            else:
                raise NameError("Invalid name option: {0}".format(k))

        if not self.path:
            self.path_cmp = None
        elif self.path_regex:
            self.path_cmp = re.compile(self.path)
        else:
            self.path_cmp = self.path
