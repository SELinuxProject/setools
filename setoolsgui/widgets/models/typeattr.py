# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
from PyQt5 import QtCore
import setools

from .. import details
from . import modelroles
from .table import SEToolsTableModel

__all__ = ("TypeAttributeTable",)


class TypeAttributeTable(SEToolsTableModel[setools.TypeAttribute]):

    """Table-based model for roles."""

    headers = ["Name", "Types"]

    def data(self, index: QtCore.QModelIndex, role: int = QtCore.Qt.ItemDataRole.DisplayRole):
        if not self.item_list or not index.isValid():
            return None

        row = index.row()
        col = index.column()
        attr = self.item_list[row]

        match role:
            case QtCore.Qt.ItemDataRole.DisplayRole:
                match col:
                    case 0:
                        return attr.name
                    case 1:
                        return ", ".join(sorted(a.name for a in sorted(attr.expand())))

            case modelroles.ContextMenuRole:
                if col == 1:
                    return (details.type_detail_action(t) for t in sorted(attr.expand()))

            case QtCore.Qt.ItemDataRole.WhatsThisRole:
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
