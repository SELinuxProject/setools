# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
from PyQt5 import QtCore
import setools

from .table import SEToolsTableModel


class FSUseTable(SEToolsTableModel[setools.FSUse]):

    """Table-based model for fs_use_*."""

    headers = ["Ruletype", "FS Type", "Context"]

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
                        return rule.ruletype.name
                    case 1:
                        return rule.fs
                    case 2:
                        return str(rule.context)

        return super().data(index, role)
