# Copyright 2019, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
from PyQt6 import QtCore
import setools

from .. import details
from .modelroles import ModelRoles
from .table import SEToolsTableModel

__all__ = ("IbpkeyconTable",)


class IbpkeyconTable(SEToolsTableModel[setools.Ibpkeycon]):

    """Table-based model for ibpkeycons."""

    headers = ["Subnet Prefix", "Partition Keys", "Context"]

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
                        return str(rule.subnet_prefix)
                    case 1:
                        low, high = rule.pkeys
                        if low == high:
                            return f"{low:#x}"
                        return f"{low:#x}-{high:#x}"
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
                            <p>This is the subnet prefix if the ibpkeycon.</p>
                            """
                    case 1:
                        column_whatsthis = \
                            """
                            <p>This is the partition key range of the ibpkeycon.</p>
                            """
                    case 2:
                        column_whatsthis = \
                            """
                            <p>This is the context of the ibpkeycon.</p>
                            """
                    case _:
                        column_whatsthis = ""

                return \
                    f"""
                    <b><p>
                    Table Representation of Infiniband Partition Key Contexts (ipbkeycon)
                    </p></b>

                    <p>Each part of the rule is represented as a column in the table.</p>

                    {column_whatsthis}
                    """

        return super().data(index, role)
