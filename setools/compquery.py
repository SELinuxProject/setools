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
# pylint: disable=no-member,attribute-defined-outside-init,abstract-method
import re

from . import query
from .descriptors import CriteriaDescriptor


class ComponentQuery(query.PolicyQuery):

    """Base class for SETools component queries."""

    name = CriteriaDescriptor("name_regex")
    name_regex = False

    def _match_name(self, obj):
        """Match the object to the name criteria."""
        if not self.name:
            # if there is no criteria, everything matches.
            return True

        return self._match_regex(obj, self.name, self.name_regex)
