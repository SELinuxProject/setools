# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
from itertools import chain

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPalette, QTextCursor

from setools.exception import NoCommon

from .table import SEToolsTableModel



class ObjClassTableModel(SEToolsTableModel):

    """Table-based model for object classes."""

    headers = ["Name", "Permissions"]

    def data(self, index, role):
        if self.item_list and index.isValid():
            row = index.row()
            col = index.column()
            item = self.item_list[row]

            if role == Qt.ItemDataRole.DisplayRole:
                if col == 0:
                    return item.name
                elif col == 1:
                    try:
                        com_perms = item.common.perms
                    except NoCommon:
                        com_perms = []

                    return ", ".join(sorted(chain(com_perms, item.perms)))

            elif role == Qt.ItemDataRole.UserRole:
                return item
