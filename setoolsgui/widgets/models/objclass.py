# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
from itertools import chain

from PyQt5 import QtCore
import setools

from . import modelroles
from .list import SEToolsListModel
from .table import SEToolsTableModel
from .. import details


class ObjClassList(SEToolsListModel[setools.ObjClass]):

    """List-based model for object classes."""

    def data(self, index: QtCore.QModelIndex, role: int = QtCore.Qt.ItemDataRole.DisplayRole):
        if not self.item_list or not index.isValid():
            return None

        row = index.row()
        item = self.item_list[row]

        match role:
            case modelroles.ContextMenuRole:
                return (details.objclass_detail_action(item), )

            case QtCore.Qt.ItemDataRole.ToolTipRole:
                return details.objclass_tooltip(item)

        return super().data(index, role)


class ObjClassTable(SEToolsTableModel[setools.ObjClass]):

    """Table-based model for object classes."""

    headers = ["Name", "Permissions"]

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
                        return item.name
                    case 1:
                        try:
                            return ", ".join(sorted(chain(item.common.perms, item.perms)))
                        except setools.exception.NoCommon:
                            return ", ".join(sorted(item.perms))

        return super().data(index, role)
