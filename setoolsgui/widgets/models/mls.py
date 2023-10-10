# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
from PyQt5 import QtCore

from .table import SEToolsTableModel

__all__ = ("MLSComponentTable",)


class MLSComponentTable(SEToolsTableModel):

    """Table-based model for sensitivities and categories."""

    headers = ["Name", "Aliases"]

    def data(self, index: QtCore.QModelIndex, role: int = QtCore.Qt.ItemDataRole.DisplayRole):
        if not self.item_list or not index.isValid():
            return None

        row = index.row()
        col = index.column()
        item = self.item_list[row]

        match role:
            case QtCore.Qt.ItemDataRole.DisplayRole:
                match col:
                    case 0:
                        return item.name
                    case 1:
                        return ", ".join(sorted(a for a in item.aliases()))

        return super().data(index, role)
