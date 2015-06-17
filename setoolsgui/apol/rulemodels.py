# Copyright 2015, Tresys Technology, LLC
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
from setools.policyrep.exception import RuleNotConditional, RuleUseError


class RuleResultModel(QAbstractTableModel):
    def __init__(self, parent):
        super(RuleResultModel, self).__init__(parent)
        self.resultlist = None

    def rowCount(self, parent=QModelIndex()):
        if self.resultlist:
            return len(self.resultlist)
        else:
            return 0

    def columnCount(self, parent=QModelIndex()):
        return 5

    def headerData(self, section, orientation, role):
        raise NotImplementedError

    def data(self, index, role):
        if role == Qt.DisplayRole:
            if not self.resultlist:
                return None

            row = index.row()
            col = index.column()

            if col == 0:
                return self.resultlist[row].ruletype
            elif col == 1:
                return str(self.resultlist[row].source)
            elif col == 2:
                return str(self.resultlist[row].target)
            elif col == 3:
                try:
                    return str(self.resultlist[row].tclass)
                except RuleUseError:
                    # role allow
                    return None
            elif col == 4:
                # most common: permissions
                try:
                    return ", ".join(sorted(self.resultlist[row].perms))
                except RuleUseError:
                    pass

                # next most common: default
                # TODO: figure out filename trans
                try:
                    return str(self.resultlist[row].default)
                except RuleUseError:
                    pass

                # least common: nothing (role allow)
                return None
            elif col == 5:
                try:
                    return str(self.resultlist[row].conditional)
                except RuleNotConditional:
                    return None
            else:
                raise ValueError("Invalid column number")
        elif role == Qt.UserRole:
            # get the whole rule for user role
            return self.resultlist[row].statement()

    def set_rules(self, result_list):
        self.beginResetModel()
        self.resultlist = result_list
        self.endResetModel()


class TERuleListModel(RuleResultModel):

    """Type Enforcement rule model.  Represents rules as a column."""

    def columnCount(self, parent=QModelIndex()):
        return 6

    def headerData(self, section, orientation, role):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            if section == 0:
                return "Rule Type"
            elif section == 1:
                return "Source"
            elif section == 2:
                return "Target"
            elif section == 3:
                return "Object Class"
            elif section == 4:
                return "Permissons/Default Type"
            elif section == 5:
                return "Conditional Expression"
            else:
                raise ValueError("Invalid column number")
