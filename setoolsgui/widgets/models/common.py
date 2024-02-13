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

__all__ = ("CommonTable",)


class CommonTable(SEToolsTableModel[setools.Common]):

    """Table-based model for common permission sets."""

    headers = ["Name", "Permissions"]

    def data(self, index: QtCore.QModelIndex, role: int = ModelRoles.DisplayRole):
        if not self.item_list or not index.isValid():
            return None

        row = index.row()
        col = index.column()
        item = self.item_list[row]

        match role:
            case ModelRoles.DisplayRole:
                match col:
                    case 0:
                        return item.name
                    case 1:
                        return ", ".join(sorted(item.perms))

            case ModelRoles.ContextMenuRole:
                return (details.common_detail_action(item), )

            case ModelRoles.ToolTipRole:
                return details.common_tooltip(item)

        return super().data(index, role)
