# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
from PyQt5 import QtCore
import setools

from .table import SEToolsTableModel


class NodeconTable(SEToolsTableModel[setools.Nodecon]):

    """Table-based model for nodecons."""

    headers = ["Network", "Context"]

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
                        return str(rule.network.with_netmask)
                    case 1:
                        return str(rule.context)

        return super().data(index, role)
