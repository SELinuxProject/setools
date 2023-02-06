# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPalette, QTextCursor

from setools.exception import NoCommon

from .details import DetailsPopup
from .models import SEToolsTableModel


def common_detail(parent, common):
    """
    Create a dialog box for common perm set details.

    Parameters:
    parent      The parent Qt Widget
    class_      The type
    """

    detail = DetailsPopup(parent, "Common detail: {0}".format(common))

    detail.append_header("Permissions ({0}):".format(len(common.perms)))
    for p in sorted(common.perms):
        detail.append("    {0}".format(p))

    detail.show()


class CommonTableModel(SEToolsTableModel):

    """Table-based model for common permission sets."""

    headers = ["Name", "Permissions"]

    def data(self, index, role):
        if self.resultlist and index.isValid():
            row = index.row()
            col = index.column()
            item = self.resultlist[row]

            if role == Qt.DisplayRole:
                if col == 0:
                    return item.name
                elif col == 1:
                    return ", ".join(sorted(item.perms))

            elif role == Qt.UserRole:
                return item
