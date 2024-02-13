# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
from PyQt6 import QtCore
import setools

from .. import details
from .modelroles import ModelRoles
from .table import SEToolsTableModel

__all__ = ("BoundsTable",)


class BoundsTable(SEToolsTableModel[setools.Bounds]):

    """Table-based model for *bounds."""

    headers = ["Rule Type", "Parent", "Child"]

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
                        return item.ruletype.name
                    case 1:
                        return item.parent.name
                    case 2:
                        return item.child.name

            case ModelRoles.ContextMenuRole:
                match col:
                    case 1:
                        return (details.type_detail_action(item.parent),)
                    case 2:
                        return (details.type_detail_action(item.child),)

            case ModelRoles.WhatsThisRole:
                match col:
                    case 0:
                        column_whatsthis = "<p>This is the rule type.</p>"
                    case 1:
                        column_whatsthis = "<p>This is the parent/bounding type.</p>"
                    case 2:
                        column_whatsthis = "<p>This is the child/bounded type.</p>"
                    case _:
                        column_whatsthis = ""

                return \
                    f"""
                    <b><p>Table Representation of bounds rules</p></b>

                    <p>Each part of the declaration is represented as a column in the table.</p>

                    {column_whatsthis}
                    """

        return super().data(index, role)
