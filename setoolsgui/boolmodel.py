# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPalette, QTextCursor

from .details import DetailsPopup
from .models import SEToolsTableModel


def boolean_detail(parent, boolean):
    """
    Create a dialog box for Booleanean details.

    Parameters:
    parent      The parent Qt Widget
    bool        The boolean
    """

    detail = DetailsPopup(parent, "Boolean detail: {0}".format(boolean))

    detail.append_header("Default State: {0}".format(boolean.state))

    detail.show()


class BooleanTableModel(SEToolsTableModel):

    """Table-based model for booleans."""

    headers = ["Name", "Default State"]

    def data(self, index, role):
        if self.resultlist and index.isValid():
            row = index.row()
            col = index.column()
            boolean = self.resultlist[row]

            if role == Qt.ItemDataRole.DisplayRole:
                if col == 0:
                    return boolean.name
                elif col == 1:
                    return str(boolean.state)

            elif role == Qt.ItemDataRole.UserRole:
                # get the whole rule for boolean boolean
                return boolean
