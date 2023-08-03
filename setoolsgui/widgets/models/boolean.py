# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
from PyQt5 import QtCore
import setools

from . import modelroles
from .list import SEToolsListModel
from .table import SEToolsTableModel
from .. import details


class BooleanList(SEToolsListModel[setools.Boolean]):

    """List-based model for Booleans."""

    def data(self, index: QtCore.QModelIndex, role: int = QtCore.Qt.ItemDataRole.DisplayRole):
        if not self.item_list or not index.isValid():
            return None

        row = index.row()
        item = self.item_list[row]

        match role:
            case modelroles.ContextMenuRole:
                return (details.boolean_detail_action(item), )
            case QtCore.Qt.ItemDataRole.ToolTipRole:
                return details.boolean_tooltip(item)

        return super().data(index, role)


class BooleanTable(SEToolsTableModel):

    """Table-based model for booleans."""

    headers = ["Name", "Default State"]

    def data(self, index: QtCore.QModelIndex, role: int = QtCore.Qt.ItemDataRole.DisplayRole):
        if not self.item_list or not index.isValid():
            return None

        row = index.row()
        col = index.column()
        boolean = self.item_list[row]

        match role:
            case QtCore.Qt.ItemDataRole.DisplayRole:
                match col:
                    case 0:
                        return boolean.name
                    case 1:
                        return str(boolean.state)

        return super().data(index, role)
