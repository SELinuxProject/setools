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

from . import query


class ComponentQuery(query.PolicyQuery):

    """Abstract base class for SETools component queries."""

    def set_name(self, name, **opts):
        """
        Set the criteria for matching the component's name.

        Parameter:
        name       Name to match the component's name.
        regex      If true, regular expression matching will be used.

        Exceptions:
        NameError  Invalid keyword option.
        """

        self.name = str(name)

        for k in opts.keys():
            if k == "regex":
                self.name_regex = opts[k]
            else:
                raise NameError("Invalid name option: {0}".format(k))

        if self.name_regex:
            self.name_cmp = re.compile(self.name)
        else:
            self.name_cmp = None
