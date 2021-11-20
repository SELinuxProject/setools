# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
from PyQt5.QtCore import Qt

from .models import SEToolsTableModel


class NodeconTableModel(SEToolsTableModel):

    """Table-based model for nodecons."""

    headers = ["Network", "Context"]

    def data(self, index, role):
        if self.resultlist and index.isValid():
            row = index.row()
            col = index.column()
            rule = self.resultlist[row]

            if role == Qt.DisplayRole:
                if col == 0:
                    return str(rule.network.with_netmask)
                elif col == 1:
                    return str(rule.context)

            elif role == Qt.UserRole:
                return rule
