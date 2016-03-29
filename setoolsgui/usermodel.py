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
from collections import defaultdict

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

    headers = defaultdict(str, {0: "Name", 1: "Roles", 2: "Default Level", 3: "Range"})

    def __init__(self, parent, mls):
        super(UserTableModel, self).__init__(parent)
        self.resultlist = []
        self.mls = mls

    def headerData(self, section, orientation, role):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self.headers[section]

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
        if self.resultlist:
            if role == Qt.DisplayRole:
                row = index.row()
                col = index.column()
                user = self.resultlist[row]

                if col == 0:
                    return str(user)
                elif col == 1:
                    return ", ".join(sorted(str(r) for r in user.roles))
                elif col == 2:
                    try:
                        return str(user.mls_level)
                    except MLSDisabled:
                        return None
                elif col == 3:
                    try:
                        return str(user.mls_range)
                    except MLSDisabled:
                        return None

            elif role == Qt.UserRole:
                return user
