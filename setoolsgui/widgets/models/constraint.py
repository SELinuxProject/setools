# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
from PyQt5.QtCore import Qt
from setools.exception import ConstraintUseError

from .table import SEToolsTableModel


class ConstraintTableModel(SEToolsTableModel):

    """A table-based model for constraints."""

    headers = ["Rule Type", "Class", "Permissions", "Expression"]

    def data(self, index, role):
        if self.item_list and index.isValid():
            row = index.row()
            col = index.column()
            rule = self.item_list[row]

            if role == Qt.ItemDataRole.DisplayRole:
                if col == 0:
                    return rule.ruletype.name
                elif col == 1:
                    return rule.tclass.name
                elif col == 2:
                    try:
                        return ", ".join(sorted(rule.perms))
                    except ConstraintUseError:
                        return None
                elif col == 3:
                    return str(rule.expression)

            elif role == Qt.ItemDataRole.UserRole:
                return rule
