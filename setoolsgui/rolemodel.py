# Copyright 2016, Tresys Technology, LLC
#
# This file is part of SETools.
#
# SETools is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation, either version 2.1 of
# the License, or (at your option) any later version.
#
# SETools is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with SETools.  If not, see
# <http://www.gnu.org/licenses/>.
#
from PyQt5.QtCore import Qt, QAbstractTableModel, QModelIndex
from PyQt5.QtGui import QPalette, QTextCursor

from setools.policyrep.exception import MLSDisabled

from .details import DetailsPopup


def role_detail(parent, role):
    """
    Create a dialog box for role details.

    Parameters:
    parent      The parent Qt Widget
    role        The role
    """

    detail = DetailsPopup(parent, "SELinux role detail: {0}".format(role))

    types = sorted(role.types())
    detail.append_header("Types ({0}): ".format(len(types)))

    for t in types:
        detail.append("    {0}".format(t))

    detail.show()


class RoleTableModel(QAbstractTableModel):

    """Table-based model for roles."""

    def __init__(self, parent):
        super(RoleTableModel, self).__init__(parent)
        self.resultlist = []

    def headerData(self, section, orientation, role):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            if section == 0:
                return "Role Name"
            elif section == 1:
                return "Types"

    def columnCount(self, parent=QModelIndex()):
        return 2

    def rowCount(self, parent=QModelIndex()):
        if self.resultlist:
            return len(self.resultlist)
        else:
            return 0

    def data(self, index, role):
        if role == Qt.DisplayRole:
            if not self.resultlist:
                return None

            row = index.row()
            col = index.column()

            if col == 0:
                return str(self.resultlist[row])
            elif col == 1:
                return ", ".join(sorted(str(t) for t in self.resultlist[row].types()))

        elif role == Qt.UserRole:
            # get the whole rule for role role
            return self.resultlist[row].statement()
