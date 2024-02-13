# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
from itertools import chain

from PyQt6 import QtCore
import setools

from .modelroles import ModelRoles
from .table import SEToolsTableModel
from .. import details

__all__ = ("ObjClassTable",)


class ObjClassTable(SEToolsTableModel[setools.ObjClass]):

    """Table-based model for object classes."""

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
                        try:
                            return ", ".join(sorted(chain(item.common.perms, item.perms)))
                        except setools.exception.NoCommon:
                            return ", ".join(sorted(item.perms))

            case ModelRoles.ContextMenuRole:
                return (details.objclass_detail_action(item), )

            case ModelRoles.ToolTipRole:
                return details.objclass_tooltip(item)

        return super().data(index, role)
