# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
from PyQt5 import QtCore
import setools

from .table import SEToolsTableModel

__all__ = ("NetifconTable",)


class NetifconTable(SEToolsTableModel[setools.Netifcon]):

    """Table-based model for netifcons."""

    headers = ["Device", "Device Context", "Packet Context"]

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
                        return rule.netif
                    case 1:
                        return str(rule.context)
                    case 2:
                        return str(rule.packet)

        return super().data(index, role)
