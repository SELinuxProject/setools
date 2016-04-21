# Copyright 2016, Tresys Technology, LLC
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
from collections import defaultdict

from PyQt5.QtCore import Qt
from setools.policyrep.exception import RuleNotConditional, RuleUseError

from .models import SEToolsTableModel


class TERuleTableModel(SEToolsTableModel):

    """A table-based model for TE rules."""

    headers = defaultdict(str, {0: "Rule Type", 1: "Source", 2: "Target",
                                3: "Object Class", 4: "Permissions/Default Type",
                                5: "Conditional Expression", 6: "Conditional Block"})

    def data(self, index, role):
        if self.resultlist and index.isValid():
            row = index.row()
            col = index.column()
            rule = self.resultlist[row]

            if role == Qt.DisplayRole:
                if col == 0:
                    return rule.ruletype
                elif col == 1:
                    return str(rule.source)
                elif col == 2:
                    return str(rule.target)
                elif col == 3:
                    return str(rule.tclass)
                elif col == 4:
                    try:
                        if rule.extended:
                            return "{0.xperm_type}: {0.perms:,}".format(rule)
                        else:
                            return ", ".join(sorted(rule.perms))
                    except RuleUseError:
                        return str(rule.default)
                elif col == 5:
                    try:
                        return str(rule.conditional)
                    except RuleNotConditional:
                        return None
                elif col == 6:
                    try:
                        return str(rule.conditional_block)
                    except RuleNotConditional:
                        return None

            elif role == Qt.UserRole:
                return rule
