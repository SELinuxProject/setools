# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
from PyQt5.QtCore import Qt

from .models import SEToolsTableModel


class FSUseTableModel(SEToolsTableModel):

    """Table-based model for fs_use_*."""

    headers = ["Ruletype", "FS Type", "Context"]

    def data(self, index, role):
        if self.resultlist and index.isValid():
            row = index.row()
            col = index.column()
            rule = self.resultlist[row]

            if role == Qt.DisplayRole:
                if col == 0:
                    return rule.ruletype.name
                elif col == 1:
                    return rule.fs
                elif col == 2:
                    return str(rule.context)

            elif role == Qt.UserRole:
                return rule
