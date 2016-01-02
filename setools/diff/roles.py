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
from collections import namedtuple

from .descriptors import DiffResultDescriptor
from .difference import Difference, SymbolWrapper


modified_roles_record = namedtuple("modified_role", ["added_types",
                                                     "removed_types",
                                                     "matched_types"])


class RolesDifference(Difference):

    """Determine the difference in roles between two policies."""

    added_roles = DiffResultDescriptor("diff_roles")
    removed_roles = DiffResultDescriptor("diff_roles")
    modified_roles = DiffResultDescriptor("diff_roles")

    def diff_roles(self):
        """Generate the difference in roles between the policies."""

        self.log.info(
            "Generating role differences from {0.left_policy} to {0.right_policy}".format(self))

        self.added_roles, self.removed_roles, matched_roles = self._set_diff(
            (SymbolWrapper(r) for r in self.left_policy.roles()),
            (SymbolWrapper(r) for r in self.right_policy.roles()))

        self.modified_roles = dict()

        for left_role, right_role in matched_roles:
            # Criteria for modified roles
            # 1. change to type set, or
            # 2. change to attribute set (not implemented)
            added_types, removed_types, matched_types = self._set_diff(
                (SymbolWrapper(t) for t in left_role.types()),
                (SymbolWrapper(t) for t in right_role.types()))

            if added_types or removed_types:
                self.modified_roles[left_role] = modified_roles_record(added_types,
                                                                       removed_types,
                                                                       matched_types)

    #
    # Internal functions
    #
    def _reset_diff(self):
        """Reset diff results on policy changes."""
        self.log.debug("Resetting role differences")
        self.added_roles = None
        self.removed_roles = None
        self.modified_roles = None
