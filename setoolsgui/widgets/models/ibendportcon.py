# Copyright 2019, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
from PyQt5 import QtCore
import setools

from .table import SEToolsTableModel

__all__ = ("IbendportconTable",)


class IbendportconTable(SEToolsTableModel[setools.Ibendportcon]):

    """Table-based model for ibendportcons."""

    headers = ["Device", "Endport", "Context"]

    def data(self, index: QtCore.QModelIndex, role: int = QtCore.Qt.ItemDataRole.DisplayRole):
        if not self.item_list or not index.isValid():
            return None

        row = index.row()
        col = index.column()
        rule = self.item_list[row]

        match role:
            case QtCore.Qt.ItemDataRole.DisplayRole:
                match col:
                    case 0:
                        return rule.name
                    case 1:
                        return str(rule.port)
                    case 2:
                        return str(rule.context)

        return super().data(index, role)
