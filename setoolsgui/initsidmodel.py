# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
from PyQt6.QtCore import Qt

from .models import SEToolsTableModel


class InitialSIDTableModel(SEToolsTableModel):

    """Table-based model for initial SIDs."""

    headers = ["SID", "Context"]

    def data(self, index, role):
        if self.resultlist and index.isValid():
            row = index.row()
            col = index.column()
            rule = self.resultlist[row]

            if role == Qt.ItemDataRole.DisplayRole:
                if col == 0:
                    return rule.name
                elif col == 1:
                    return str(rule.context)

            elif role == Qt.ItemDataRole.UserRole:
                return rule
