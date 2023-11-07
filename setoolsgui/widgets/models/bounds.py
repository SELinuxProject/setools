# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
from PyQt6 import QtCore
import setools

from .table import SEToolsTableModel

__all__ = ("BoundsTable",)


class BoundsTable(SEToolsTableModel[setools.Bounds]):

    """Table-based model for *bounds."""

    headers = ["Rule Type", "Parent", "Child"]

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
                        return item.ruletype.name
                    case 1:
                        return item.parent.name
                    case 2:
                        return item.child.name

        return super().data(index, role)
