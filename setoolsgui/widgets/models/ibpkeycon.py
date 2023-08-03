# Copyright 2019, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
from PyQt5 import QtCore
import setools

from .table import SEToolsTableModel


class IbpkeyconTable(SEToolsTableModel[setools.Ibpkeycon]):

    """Table-based model for ibpkeycons."""

    headers = ["Subnet Prefix", "Partition Keys", "Context"]

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
                        return str(rule.subnet_prefix)
                    case 1:
                        low, high = rule.pkeys
                        if low == high:
                            return f"{low:#x}"
                        return f"{low:#x}-{high:#x}"
                    case 2:
                        return str(rule.context)

        return super().data(index, role)
