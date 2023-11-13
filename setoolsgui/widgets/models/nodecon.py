# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
from PyQt6 import QtCore
import setools

from .. import details
from . import modelroles
from .table import SEToolsTableModel

__all__ = ("NodeconTable",)


class NodeconTable(SEToolsTableModel[setools.Nodecon]):

    """Table-based model for nodecons."""

    headers = ["Network", "Context"]

    def data(self, index: QtCore.QModelIndex, role: int = QtCore.Qt.ItemDataRole.DisplayRole):
        if not self.item_list or not index.isValid():
            return None

        row = index.row()
        col = index.column()
        rule = self.item_list[row]

        match role:
            case QtCore.Qt.ItemDataRole.DisplayRole:
                match col:
                    case 0:
                        return str(rule.network.with_netmask)
                    case 1:
                        return str(rule.context)

            case modelroles.ContextMenuRole:
                if col == 1:
                    return details.context_detail_action(rule.context)

            case QtCore.Qt.ItemDataRole.WhatsThisRole:
                match col:
                    case 0:
                        column_whatsthis = \
                            """
                            <p>This is the network of the nodecon.</p>
                            """
                    case 2:
                        column_whatsthis = \
                            """
                            <p>This is the context of the nodecon.</p>
                            """
                    case _:
                        column_whatsthis = ""

                return \
                    f"""
                    <b><p>Table Representation of Network Node Contexts (nodecon)</p></b>

                    <p>Each part of the rule is represented as a column in the table.</p>

                    {column_whatsthis}
                    """

        return super().data(index, role)
