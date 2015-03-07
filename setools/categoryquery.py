# Copyright 2015, Tresys Technology, LLC
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


class CategoryQuery(compquery.ComponentQuery):

    """Query MLS Categories"""

    def __init__(self, policy,
                 name="", name_regex=False,
                 alias="", alias_regex=False):
        """
        Parameters:
        name         The name of the category to match.
        name_regex   If true, regular expression matching will
                     be used for matching the name.
        alias        The alias name to match.
        alias_regex  If true, regular expression matching
                     will be used on the alias names.
        """

        self.policy = policy
        self.set_name(name, regex=name_regex)
        self.set_alias(alias, regex=alias_regex)

    def results(self):
        """Generator which yields all matching categories."""

        for cat in self.policy.categories():
            if self.name and not self._match_regex(
                    cat,
                    self.name_cmp,
                    self.name_regex):
                continue

            if self.alias and not self._match_in_set(
                    cat.aliases(),
                    self.alias_cmp,
                    self.alias_regex):
                continue

            yield cat

    def set_alias(self, alias, **opts):
        """
        Set the criteria for the category's aliases.

        Parameter:
        alias       Name to match the category's aliases.

        Keyword Options:
        regex       If true, regular expression matching will be used.

        Exceptions:
        NameError   Invalid keyword option.
        """

        self.alias = alias

        for k in list(opts.keys()):
            if k == "regex":
                self.alias_regex = opts[k]
            else:
                raise NameError("Invalid alias option: {0}".format(k))

        if not self.alias:
            self.alias_cmp = None
        elif self.alias_regex:
            self.alias_cmp = re.compile(self.alias)
        else:
            self.alias_cmp = self.alias
