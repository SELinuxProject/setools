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

__all__ = ("TypeAttributeTable",)


class TypeAttributeTable(SEToolsTableModel[setools.TypeAttribute]):

    """Table-based model for roles."""

    headers = ["Name", "Types"]

    def data(self, index: QtCore.QModelIndex, role: int = ModelRoles.DisplayRole):
        if not self.item_list or not index.isValid():
            return None

        row = index.row()
        col = index.column()
        attr = self.item_list[row]

        match role:
            case ModelRoles.DisplayRole:
                match col:
                    case 0:
                        return attr.name
                    case 1:
                        return ", ".join(sorted(a.name for a in sorted(attr.expand())))

            case ModelRoles.ContextMenuRole:
                match col:
                    case 0:
                        return (details.typeattr_detail_action(attr),)
                    case 1:
                        return (details.type_detail_action(t) for t in sorted(attr.expand()))

            case ModelRoles.WhatsThisRole:
                match col:
                    case 0:
                        column_whatsthis = "<p>This is the name of the type attribute.</p>"
                    case 1:
                        column_whatsthis = \
                            "<p>This is the list of types associated with the attribute.</p>"
                    case _:
                        column_whatsthis = ""

                return \
                    f"""
                    <b><p>Table Representation of SELinux users</p></b>

                    <p>Each part of the declaration is represented as a column in the table.</p>

                    {column_whatsthis}
                    """

        return super().data(index, role)
