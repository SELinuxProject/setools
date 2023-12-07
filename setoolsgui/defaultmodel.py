# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
from contextlib import suppress

from PyQt5.QtCore import Qt

from .models import SEToolsTableModel


class DefaultTableModel(SEToolsTableModel):

    """Table-based model for default_*."""

    headers = ["Rule Type", "Class", "Default", "Default Range"]

    def data(self, index, role):
        if self.resultlist and index.isValid():
            row = index.row()
            col = index.column()
            item = self.resultlist[row]

            if role == Qt.ItemDataRole.DisplayRole:
                if col == 0:
                    return item.ruletype.name
                elif col == 1:
                    return item.tclass.name
                elif col == 2:
                    return item.default.name
                elif col == 3:
                    with suppress(AttributeError):
                        return item.default_range.name

            elif role == Qt.ItemDataRole.UserRole:
                return item
