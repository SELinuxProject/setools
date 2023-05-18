# Copyright 2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
import logging
import typing

from PyQt5 import QtCore

from . import modelroles
from .typing import MetaclassFix

T = typing.TypeVar("T")


class SEToolsListModel(QtCore.QAbstractListModel, typing.Generic[T], metaclass=MetaclassFix):

    """
    The purpose of this model is to have the
    objects return their string representations
    for Qt.DisplayRole and return the object
    for Qt.UserRole.

    Some Python list-like functions are provided
    for altering the model: append and remove
    """

    def __init__(self, parent: QtCore.QObject | None = None) -> None:
        super().__init__(parent)
        self.log = logging.getLogger(self.__module__)
        self._item_list: typing.List[T] = []

    @property
    def item_list(self) -> typing.List[T]:
        """The list of items in the model."""
        return self._item_list

    @item_list.setter
    def item_list(self, item_list: typing.List[T]) -> None:
        self.beginResetModel()
        self._item_list = item_list
        self.endResetModel()

    def rowCount(self, parent=QtCore.QModelIndex()) -> int:
        """The number of rows in the model."""
        return len(self.item_list)

    def columnCount(self, parent=QtCore.QModelIndex()) -> int:
        """The number of columns in the model."""
        return 1

    def append(self, item: T) -> None:
        """Append the item to the list."""
        index = self.rowCount()
        self.beginInsertRows(QtCore.QModelIndex(), index, index)
        self.item_list.append(item)
        self.endInsertRows()

    def remove(self, item: T) -> None:
        """Remove the first instance of the specified item from the list."""
        try:
            row = self.item_list.index(item)
            self.beginRemoveRows(QtCore.QModelIndex(), row, row)
            del self.item_list[row]
            self.endRemoveRows()
        except ValueError:
            self.log.debug(f"Attempted to remove item {item!r} but it is not in the list")

    def data(self, index: QtCore.QModelIndex, role: int = QtCore.Qt.ItemDataRole.DisplayRole):
        """Get the data at the specified index for the specified role."""
        if not self.item_list or not index.isValid():
            return None

        row = index.row()
        item = self.item_list[row]

        match role:
            case QtCore.Qt.ItemDataRole.DisplayRole:
                return str(item)
            case modelroles.PolicyObjRole:
                return item
            case modelroles.ContextMenuRole:
                return ()
            case _:
                return None

    def flags(self, index: QtCore.QModelIndex = QtCore.QModelIndex()) -> QtCore.Qt.ItemFlags:
        """Get the flags for the specified index."""
        return QtCore.Qt.ItemFlags() | \
            QtCore.Qt.ItemFlag.ItemIsEnabled | \
            QtCore.Qt.ItemFlag.ItemIsSelectable | \
            QtCore.Qt.ItemFlag.ItemNeverHasChildren
