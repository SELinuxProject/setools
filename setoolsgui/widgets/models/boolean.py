# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
from typing import TYPE_CHECKING

from PyQt5 import QtCore, QtWidgets

from . import modelroles
from .list import SEToolsListModel
from .table import SEToolsTableModel
from .. import details

if TYPE_CHECKING:
    from setools import Boolean


class BooleanList(SEToolsListModel["Boolean"]):

    """List-based model for Booleans."""

    def data(self, index: QtCore.QModelIndex, role: int = QtCore.Qt.ItemDataRole.DisplayRole):
        if not self.item_list or not index.isValid():
            return None

        row = index.row()
        item = self.item_list[row]

        if role == modelroles.ContextMenuRole:
            return (details.boolean_detail_action(item), )
        elif role == QtCore.Qt.ItemDataRole.ToolTipRole:
            return details.boolean_tooltip(item)

        return super().data(index, role)


class BooleanTableModel(SEToolsTableModel):

    """Table-based model for booleans."""

    headers = ["Name", "Default State"]

    def data(self, index, role):
        if self.item_list and index.isValid():
            row = index.row()
            col = index.column()
            boolean = self.item_list[row]

            if role == QtCore.Qt.ItemDataRole.DisplayRole:
                if col == 0:
                    return boolean.name
                elif col == 1:
                    return str(boolean.state)

            elif role == QtCore.Qt.ItemDataRole.UserRole:
                # get the whole rule for boolean boolean
                return boolean
