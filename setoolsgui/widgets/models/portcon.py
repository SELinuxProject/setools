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

__all__ = ("PortconTable",)


class PortconTable(SEToolsTableModel[setools.Portcon]):

    """Table-based model for portcons."""

    headers = ["Port/Port Range", "Protocol", "Context"]

    def data(self, index: QtCore.QModelIndex, role: int = ModelRoles.DisplayRole):
        if not self.item_list or not index.isValid():
            return None

        row: int = index.row()
        col: int = index.column()
        rule = self.item_list[row]

        match role:
            case ModelRoles.DisplayRole:
                match col:
                    case 0:
                        low, high = rule.ports.low, rule.ports.high
                        if low == high:
                            return str(low)
                        return f"{low}-{high}"
                    case 1:
                        return rule.protocol.name
                    case 2:
                        return str(rule.context)

            case ModelRoles.ContextMenuRole:
                if col == 2:
                    return details.context_detail_action(rule.context)

            case ModelRoles.WhatsThisRole:
                match col:
                    case 0:
                        column_whatsthis = \
                            """
                            <p>This is the port number or port number range of the portcon.</p>
                            """
                    case 1:
                        column_whatsthis = \
                            """
                            <p>This is the protocol of the portcon.</p>
                            """
                    case 2:
                        column_whatsthis = \
                            """
                            <p>This is the context of the portcon.</p>
                            """
                    case _:
                        column_whatsthis = ""

                return \
                    f"""
                    <b><p>Table Representation of Network Port Contexts (portcon)</p></b>

                    <p>Each part of the rule is represented as a column in the table.</p>

                    {column_whatsthis}
                    """

        return super().data(index, role)
