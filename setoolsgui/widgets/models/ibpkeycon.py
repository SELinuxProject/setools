# Copyright 2019, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
from PyQt5.QtCore import Qt

from .models import SEToolsTableModel


class IbpkeyconTableModel(SEToolsTableModel):

    """Table-based model for ibpkeycons."""

    headers = ["Subnet Prefix", "Partition Keys", "Context"]

    def data(self, index, role):
        if self.resultlist and index.isValid():
            row = index.row()
            col = index.column()
            rule = self.resultlist[row]

            if role == Qt.ItemDataRole.DisplayRole:
                if col == 0:
                    return str(rule.subnet_prefix)
                elif col == 1:
                    low, high = rule.pkeys
                    if low == high:
                        return "{0:#x}".format(low)
                    else:
                        return "{0:#x}-{1:#x}".format(low, high)
                elif col == 2:
                    return str(rule.context)

            elif role == Qt.ItemDataRole.UserRole:
                return rule
