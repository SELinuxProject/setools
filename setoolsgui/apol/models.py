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

from PyQt5 import QtCore
from PyQt5.QtCore import QAbstractListModel, QModelIndex, QStringListModel, Qt
from setools.policyrep.exception import NoCommon


class SEToolsListModel(QAbstractListModel):

    """
    The purpose of this model is to have the
    objects return their string representations
    for Qt.DisplayRole and return the object
    for Qt.UserRole.
    """

    def __init__(self, parent):
        super(SEToolsListModel, self).__init__(parent)
        self._item_list = None

    @property
    def item_list(self):
        return self._item_list

    @item_list.setter
    def item_list(self, item_list):
        self.beginResetModel()
        self._item_list = item_list
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        if self.item_list:
            return len(self.item_list)
        else:
            return 0

    def columnCount(self, parent=QModelIndex()):
        return 1

    def data(self, index, role):
        if self.item_list:
            row = index.row()

            if role == Qt.DisplayRole:
                return str(self.item_list[row])
            elif role == Qt.UserRole:
                return self.item_list[row]


class PermListModel(SEToolsListModel):

    """
    A model that will return the intersection of permissions
    for the selected classes.  If no classes are
    set, all permissions in the policy will be returned.
    """

    def __init__(self, parent, policy):
        super(PermListModel, self).__init__(parent)
        self.policy = policy
        self.set_classes()

    def set_classes(self, classes=[]):
        permlist = set()

        # start will all permissions.
        for cls in self.policy.classes():
            permlist.update(cls.perms)

            try:
                permlist.update(cls.common.perms)
            except NoCommon:
                pass

        # create intersection
        for cls in classes:
            cls_perms = cls.perms

            try:
                cls_perms.update(cls.common.perms)
            except NoCommon:
                pass

            permlist.intersection_update(cls_perms)

        self.item_list = sorted(permlist)
