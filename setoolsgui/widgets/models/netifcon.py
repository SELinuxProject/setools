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

__all__ = ("NetifconTable",)


class NetifconTable(SEToolsTableModel[setools.Netifcon]):

    """Table-based model for netifcons."""

    headers = ["Device", "Device Context", "Packet Context"]

    def data(self, index: QtCore.QModelIndex, role: int = ModelRoles.DisplayRole):
        if not self.item_list or not index.isValid():
            return None

        row = index.row()
        col = index.column()
        rule = self.item_list[row]

        match role:
            case ModelRoles.DisplayRole:
                match col:
                    case 0:
                        return rule.netif
                    case 1:
                        return str(rule.context)
                    case 2:
                        return str(rule.packet)

            case ModelRoles.ContextMenuRole:
                match col:
                    case 1:
                        return details.context_detail_action(rule.context)
                    case 2:
                        return details.context_detail_action(rule.packet)

            case ModelRoles.WhatsThisRole:
                match col:
                    case 0:
                        column_whatsthis = \
                            """
                            <p>This is the name of the netifcon.</p>
                            """
                    case 1:
                        column_whatsthis = \
                            """
                            <p>This is the device context of the netifcon.</p>
                            """
                    case 2:
                        column_whatsthis = \
                            """
                            <p>This is the packet context of the netifcon.</p>
                            """
                    case _:
                        column_whatsthis = ""

                return \
                    f"""
                    <b><p>Table Representation of Network Interface Contexts (netifcon)</p></b>

                    <p>Each part of the rule is represented as a column in the table.</p>

                    {column_whatsthis}
                    """

        return super().data(index, role)
