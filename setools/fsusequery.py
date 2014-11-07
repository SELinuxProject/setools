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


class FSUseQuery(contextquery.ContextQuery):

    """Query fs_use_* statements."""

    def __init__(self, policy,
                 ruletype=[],
                 fs="", fs_regex=False,
                 user="", user_regex=False,
                 role="", role_regex=False,
                 type_="", type_regex=False,
                 range_=""):
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
        """

        self.policy = policy

        self.set_ruletype(ruletype)
        self.set_fs(fs, regex=fs_regex)
        self.set_user(user, regex=user_regex)
        self.set_role(role, regex=role_regex)
        self.set_type(type_, regex=type_regex)
        self.set_range(range_)

    def results(self):
        """Generator which yields all matching fs_use_* statements."""

        for fsu in self.policy.fs_uses():
            if self.ruletype and not fsu.ruletype in self.ruletype:
                continue

            if self.fs and not self._match_regex(
                    fsu.fs,
                    self.fs,
                    self.fs_regex,
                    self.fs_cmp):
                continue

            if not self._match_context(
                    fsu.context,
                    self.user,
                    self.user_regex,
                    self.user_cmp,
                    self.role,
                    self.role_regex,
                    self.role_cmp,
                    self.type_,
                    self.type_regex,
                    self.type_cmp,
                    self.range_):
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
