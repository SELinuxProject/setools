# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
import typing

from PyQt6 import QtCore
import setools

from .. import details
from .modelroles import ModelRoles
from .table import SEToolsTableModel

__all__ = ("UserTable",)


class UserTable(SEToolsTableModel[setools.User]):

    """Table-based model for users."""

    headers = ["Name", "Roles", "Default Level", "Range"]

    def __init__(self, /, parent: QtCore.QObject | None = None, *,
                 data: typing.Iterable[setools.User] | None = None,
                 mls: bool = False):

        super().__init__(data=data, parent=parent)
        self.mls: typing.Final[bool] = mls

    def columnCount(self, parent=QtCore.QModelIndex()) -> int:
        return 4 if self.mls else 2

    def data(self, index: QtCore.QModelIndex, role: int = ModelRoles.DisplayRole):
        if not self.item_list or not index.isValid():
            return None

        row = index.row()
        col = index.column()
        user = self.item_list[row]

        match role:
            case ModelRoles.DisplayRole:
                match col:
                    case 0:
                        return user.name
                    case 1:
                        return ", ".join(sorted(r.name for r in user.roles))
                    case 2:
                        return str(user.mls_level)
                    case 3:
                        return str(user.mls_range)

            case ModelRoles.ContextMenuRole:
                match col:
                    case 0:
                        return (details.user_detail_action(user),)
                    case 1:
                        return (details.role_detail_action(r) for r in sorted(user.roles))

            case ModelRoles.WhatsThisRole:
                match col:
                    case 0:
                        column_whatsthis = "<p>This is the name of the user.</p>"
                    case 1:
                        column_whatsthis = \
                            "<p>This is the list of roles associated with the user.</p>"
                    case 2:
                        column_whatsthis = "<p>This is the default MLS level of the user.</p>"
                    case 3:
                        column_whatsthis = "<p>This is allowed range for the user.</p>"
                    case _:
                        column_whatsthis = ""

                return \
                    f"""
                    <b><p>Table Representation of SELinux users</p></b>

                    <p>Each part of the declaration is represented as a column in the table.</p>

                    {column_whatsthis}
                    """

        return super().data(index, role)
