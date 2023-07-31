# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
from itertools import chain
from typing import TYPE_CHECKING

from PyQt5 import QtCore, QtWidgets
from setools.exception import NoCommon

from . import modelroles
from .list import SEToolsListModel
from .table import SEToolsTableModel
from .. import details

if TYPE_CHECKING:
    from setools import ObjClass


class ObjClassList(SEToolsListModel["ObjClass"]):

    """List-based model for object classes."""

    def data(self, index: QtCore.QModelIndex, role: int = QtCore.Qt.ItemDataRole.DisplayRole):
        if not self.item_list or not index.isValid():
            return None

        row = index.row()
        item = self.item_list[row]

        if role == modelroles.ContextMenuRole:
            return (details.objclass_detail_action(item), )
        elif role == QtCore.Qt.ItemDataRole.ToolTipRole:
            return details.objclass_tooltip(item)

        return super().data(index, role)


class ObjClassTableModel(SEToolsTableModel["ObjClass"]):

    """Table-based model for object classes."""

    headers = ["Name", "Permissions"]

    def data(self, index, role):
        if self.item_list and index.isValid():
            row = index.row()
            col = index.column()
            item = self.item_list[row]

            if role == QtCore.Qt.ItemDataRole.DisplayRole:
                if col == 0:
                    return item.name
                elif col == 1:
                    try:
                        com_perms = item.common.perms
                    except NoCommon:
                        com_perms = []

                    return ", ".join(sorted(chain(com_perms, item.perms)))

            elif role == QtCore.Qt.ItemDataRole.UserRole:
                return item
