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

__all__ = ("RoleTable",)


class RoleTable(SEToolsTableModel[setools.Role]):

    """Table-based model for roles."""

    headers = ["Name", "Types"]

    def data(self, index: QtCore.QModelIndex, role: int = ModelRoles.DisplayRole):
        if not self.item_list or not index.isValid():
            return None

        # There are two roles here.
        # The parameter, role, is the Qt role
        # The below item is a role in the list.
        row = index.row()
        col = index.column()
        item = self.item_list[row]

        match role:
            case ModelRoles.DisplayRole:
                match col:
                    case 0:
                        return item.name
                    case 1:
                        return ", ".join(sorted(t.name for t in item.types()))

            case ModelRoles.ContextMenuRole:
                match col:
                    case 0:
                        return (details.role_detail_action(item),)
                    case 1:
                        return (details.type_detail_action(t) for t in sorted(item.types()))

            case ModelRoles.WhatsThisRole:
                match col:
                    case 0:
                        column_whatsthis = "<p>This is the name of the role.</p>"
                    case 1:
                        column_whatsthis = \
                            "<p>This is the list of types associated with this role.</p>"
                    case _:
                        column_whatsthis = ""

                return \
                    f"""
                    <b><p>Table Representation of Roles</p></b>

                    <p>Each part of the declaration is represented as a column in the table.</p>

                    {column_whatsthis}
                    """

        return super().data(index, role)
