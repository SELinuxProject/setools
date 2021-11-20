# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
from PyQt5.QtCore import Qt

from .models import SEToolsTableModel


class BoundsTableModel(SEToolsTableModel):

    """Table-based model for *bounds."""

    headers = ["Rule Type", "Parent", "Child"]

    def data(self, index, role):
        if self.resultlist and index.isValid():
            row = index.row()
            col = index.column()
            item = self.resultlist[row]

            if role == Qt.DisplayRole:
                if col == 0:
                    return item.ruletype.name
                elif col == 1:
                    return item.parent.name
                elif col == 2:
                    return item.child.name

            elif role == Qt.UserRole:
                return item
