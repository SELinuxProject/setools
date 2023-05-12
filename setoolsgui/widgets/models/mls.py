# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPalette, QTextCursor

from .details import DetailsPopup
from .models import SEToolsTableModel


def _mls_detail(parent, obj, objtype):
    """
    Create a dialog box for category or sensitivity details.

    Parameters:
    parent      The parent Qt Widget
    type_       The type
    """

    detail = DetailsPopup(parent, "{0} detail: {1}".format(objtype, obj))

    aliases = sorted(obj.aliases())
    detail.append_header("Aliases ({0}):".format(len(aliases)))
    for a in aliases:
        detail.append("    {0}".format(a))

    detail.show()


def category_detail(parent, obj):
    """
    Create a dialog box for category details.

    Parameters:
    parent      The parent Qt Widget
    type_       The type
    """
    _mls_detail(parent, obj, "Category")


def sensitivity_detail(parent, obj):
    """
    Create a dialog box for sensitivity details.

    Parameters:
    parent      The parent Qt Widget
    type_       The type
    """
    _mls_detail(parent, obj, "Sensitivity")


class MLSComponentTableModel(SEToolsTableModel):

    """Table-based model for sensitivities and categories."""

    headers = ["Name", "Aliases"]

    def data(self, index, role):
        if self.resultlist and index.isValid():
            row = index.row()
            col = index.column()
            item = self.resultlist[row]

            if role == Qt.ItemDataRole.DisplayRole:
                if col == 0:
                    return item.name
                elif col == 1:
                    return ", ".join(sorted(a for a in item.aliases()))

            elif role == Qt.ItemDataRole.UserRole:
                return item
