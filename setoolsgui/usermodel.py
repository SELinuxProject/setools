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
from setools.policyrep.exception import MLSDisabled

from .details import DetailsPopup


def user_detail(parent, user):
    """
    Create a dialog box for user details.

    Parameters:
    parent      The parent Qt Widget
    user        The user
    """

    detail = DetailsPopup(parent, "User detail: {0}".format(user))

    roles = sorted(user.roles)
    detail.append_header("Roles ({0}):".format(len(roles)))

    for r in roles:
        detail.append("    {0}".format(r))

    try:
        l = user.mls_level
        r = user.mls_range
    except MLSDisabled:
        pass
    else:
        detail.append_header("\nDefault MLS Level:")
        detail.append("    {0}".format(l))
        detail.append_header("\nMLS Range:")
        detail.append("    {0}".format(r))

    detail.show()


class UserTableModel(QAbstractTableModel):

    """Table-based model for users."""

    def __init__(self, parent, mls):
        super(UserTableModel, self).__init__(parent)
        self.resultlist = []
        self.mls = mls

    def headerData(self, section, orientation, role):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            if section == 0:
                return "Name"
            elif section == 1:
                return "Roles"
            elif section == 2:
                return "Default Level"
            elif section == 3:
                return "Range"

    def columnCount(self, parent=QModelIndex()):
        if self.mls:
            return 4
        else:
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
                return ", ".join(sorted(str(r) for r in self.resultlist[row].roles))
            elif col == 2:
                try:
                    return str(self.resultlist[row].mls_level)
                except MLSDisabled:
                    return None
            elif col == 3:
                try:
                    return str(self.resultlist[row].mls_range)
                except MLSDisabled:
                    return None

        elif role == Qt.UserRole:
            # get the whole rule for user role
            return self.resultlist[row].statement()
