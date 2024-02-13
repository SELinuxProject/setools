# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
from PyQt6 import QtCore
import setools

from .modelroles import ModelRoles
from .table import SEToolsTableModel
from .. import details

__all__ = ("BooleanTable",)


class BooleanTable(SEToolsTableModel[setools.Boolean]):

    """Table-based model for booleans."""

    headers = ["Name", "Default State"]

    def data(self, index: QtCore.QModelIndex, role: int = ModelRoles.DisplayRole):
        if not self.item_list or not index.isValid():
            return None

        row = index.row()
        col = index.column()
        boolean = self.item_list[row]

        match role:
            case ModelRoles.DisplayRole:
                match col:
                    case 0:
                        return boolean.name
                    case 1:
                        return str(boolean.state)

            case ModelRoles.ContextMenuRole:
                return (details.boolean_detail_action(boolean), )

            case ModelRoles.ToolTipRole:
                return details.boolean_tooltip(boolean)

        return super().data(index, role)
