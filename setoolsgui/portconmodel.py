# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
from PyQt5.QtCore import Qt

from .models import SEToolsTableModel


class PortconTableModel(SEToolsTableModel):

    """Table-based model for portcons."""

    headers = ["Port/Port Range", "Protocol", "Context"]

    def data(self, index, role):
        if self.resultlist and index.isValid():
            row = index.row()
            col = index.column()
            rule = self.resultlist[row]

            if role == Qt.DisplayRole:
                if col == 0:
                    low, high = rule.ports
                    if low == high:
                        return str(low)
                    else:
                        return "{0}-{1}".format(low, high)
                elif col == 1:
                    return rule.protocol.name
                elif col == 2:
                    return str(rule.context)

            elif role == Qt.UserRole:
                return rule
