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

__all__ = ("InitialSIDTable",)


class InitialSIDTable(SEToolsTableModel[setools.InitialSID]):

    """Table-based model for initial SIDs."""

    headers = ["Name", "Context"]

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
                        return rule.name
                    case 1:
                        return str(rule.context)

            case ModelRoles.ContextMenuRole:
                if col == 1:
                    return details.context_detail_action(rule.context)

            case ModelRoles.WhatsThisRole:
                match col:
                    case 0:
                        column_whatsthis = \
                            """
                            <p>This is the name of the initial context.</p>
                            """
                    case 1:
                        column_whatsthis = \
                            """
                            <p>This is the context of the initial context.</p>
                            """
                    case _:
                        column_whatsthis = ""

                return \
                    f"""
                    <b><p>Table Representation of Initial Contexts (sid)</p></b>

                    <p>Each part of the rule is represented as a column in the table.</p>

                    {column_whatsthis}
                    """

        return super().data(index, role)
