# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPalette, QTextCursor

from setools.exception import MLSDisabled

from .details import DetailsPopup
from .models import SEToolsTableModel


def typeattr_detail(parent, attr):
    """
    Create a dialog box for attribute details.

    Parameters:
    parent      The parent Qt Widget
    role        The role
    """

    detail = DetailsPopup(parent, "Type attribute detail: {0}".format(attr))

    types = sorted(attr.expand())
    detail.append_header("Types ({0}): ".format(len(types)))

    for t in types:
        detail.append("    {0}".format(t))

    detail.show()


class TypeAttributeTableModel(SEToolsTableModel):

    """Table-based model for roles."""

    headers = ["Name", "Types"]

    def data(self, index, role):
        if self.resultlist and index.isValid():
            row = index.row()
            col = index.column()
            item = self.resultlist[row]

            if role == Qt.ItemDataRole.DisplayRole:
                if col == 0:
                    return item.name
                elif col == 1:
                    return ", ".join(sorted(t.name for t in item.expand()))

            elif role == Qt.ItemDataRole.UserRole:
                return item
