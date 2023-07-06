# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
from PyQt5.QtCore import Qt

from .table import SEToolsTableModel


class TypeTableModel(SEToolsTableModel):

    """Table-based model for types."""

    headers = ["Name", "Attributes", "Aliases", "Permissive"]

    def data(self, index, role):
        if self.item_list and index.isValid():
            row = index.row()
            col = index.column()
            item = self.item_list[row]

            if role == Qt.ItemDataRole.DisplayRole:
                if col == 0:
                    return item.name
                elif col == 1:
                    return ", ".join(sorted(a.name for a in item.attributes()))
                elif col == 2:
                    return ", ".join(sorted(a for a in item.aliases()))
                elif col == 3 and item.ispermissive:
                    return "Permissive"

            elif role == Qt.ItemDataRole.UserRole:
                return item
