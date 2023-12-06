# Copyright 2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
import logging
from contextlib import suppress
from typing import List

from PyQt5.QtCore import QAbstractListModel, QItemSelectionModel, QAbstractTableModel, \
    QModelIndex, QStringListModel, Qt
from setools.exception import NoCommon


def invert_list_selection(selection_model):
    """Invert the selection of a list-based model."""

    model = selection_model.model()
    rowcount = model.rowCount()
    for row in range(rowcount):
        index = model.createIndex(row, 0)
        selection_model.select(index, QItemSelectionModel.SelectionFlag.Toggle)


class SEToolsListModel(QAbstractListModel):

    """
    The purpose of this model is to have the
    objects return their string representations
    for Qt.ItemDataRole.DisplayRole and return the object
    for Qt.ItemDataRole.UserRole.

    Some Python list-like functions are provided
    for altering the model: append and remove
    """

    def __init__(self, parent):
        super(SEToolsListModel, self).__init__(parent)
        self.log = logging.getLogger(__name__)
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

    def append(self, item):
        """Append the item to the list."""
        index = self.rowCount()
        self.beginInsertRows(QModelIndex(), index, index)
        self.item_list.append(item)
        self.endInsertRows()

    def remove(self, item):
        """Remove the first instance of the specified item from the list."""
        try:
            row = self.item_list.index(item)
        except ValueError:
            self.log.debug("Attempted to remove item {0!r} but it is not in the list".format(item))
        else:
            self.beginRemoveRows(QModelIndex(), row, row)
            del self.item_list[row]
            self.endRemoveRows()

    def data(self, index, role):
        if self.item_list and index.isValid():
            row = index.row()
            item = self.item_list[row]

            if role == Qt.ItemDataRole.DisplayRole:
                return str(item)
            elif role == Qt.ItemDataRole.UserRole:
                return item


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

            with suppress(NoCommon):
                permlist.update(cls.common.perms)

        # create intersection
        for cls in classes:
            cls_perms = set(cls.perms)

            with suppress(NoCommon):
                cls_perms.update(cls.common.perms)

            permlist.intersection_update(cls_perms)

        self.item_list = sorted(permlist)


class SEToolsTableModel(QAbstractTableModel):

    """Base class for SETools table models."""

    headers: List[str] = []

    def __init__(self, parent):
        super(SEToolsTableModel, self).__init__(parent)
        self.resultlist = []

    def headerData(self, section, orientation, role):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self.headers[section]

    def rowCount(self, parent=QModelIndex()):
        if self.resultlist:
            return len(self.resultlist)
        else:
            return 0

    def columnCount(self, parent=QModelIndex()):
        return len(self.headers)

    def data(self, index, role):
        raise NotImplementedError
