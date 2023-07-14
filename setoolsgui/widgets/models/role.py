# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPalette, QTextCursor

from setools.exception import MLSDisabled

from .table import SEToolsTableModel


class RoleTableModel(SEToolsTableModel):

    """Table-based model for roles."""

    headers = ["Name", "Types"]

    def data(self, index, role):
        # There are two roles here.
        # The parameter, role, is the Qt role
        # The below item is a role in the list.
        if self.item_list and index.isValid():
            row = index.row()
            col = index.column()
            item = self.item_list[row]

            if role == Qt.ItemDataRole.DisplayRole:
                if col == 0:
                    return item.name
                elif col == 1:
                    return ", ".join(sorted(t.name for t in item.types()))
            elif role == Qt.ItemDataRole.UserRole:
                # get the whole object
                return item
