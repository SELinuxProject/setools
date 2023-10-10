# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
from PyQt5 import QtCore
import setools

from .table import SEToolsTableModel

__all__ = ("PortconTable",)


class PortconTable(SEToolsTableModel[setools.Portcon]):

    """Table-based model for portcons."""

    headers = ["Port/Port Range", "Protocol", "Context"]

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
                        low, high = rule.ports
                        if low == high:
                            return str(low)
                        return f"{low}-{high}"
                    case 1:
                        return rule.protocol.name
                    case 2:
                        return str(rule.context)

        return super().data(index, role)
