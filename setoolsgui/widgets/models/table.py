# Copyright 2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
import logging
import typing

from PyQt6 import QtCore

from .modelroles import ModelRoles
from .typing import AllStdDataTypes, ContextMenuType, MetaclassFix

T = typing.TypeVar("T")

__all__ = ("SEToolsTableModel", "StringList")


# pylint: disable=invalid-metaclass
class SEToolsTableModel(QtCore.QAbstractTableModel, typing.Generic[T], metaclass=MetaclassFix):

    """Base class for SETools table models, modeling a list in a tabular form."""

    headers: typing.List[str]

    def __init__(self, /, parent: QtCore.QObject | None = None, *,
                 data: typing.Iterable[T] | None = None):

        super().__init__(parent)
        self.log = logging.getLogger(self.__module__)
        if data is not None:
            self._item_list = list(data)
        else:
            self._item_list = []

    #
    # Add/remove/set model data
    #
    @property
    def item_list(self) -> typing.List[T]:
        """The list of items in the model."""
        return self._item_list

    @item_list.setter
    def item_list(self, item_list: typing.List[T]) -> None:
        self.beginResetModel()
        self._item_list = item_list
        self.endResetModel()

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

    #
    # Qt API implementation
    #
    def headerData(self, section: int, orientation: QtCore.Qt.Orientation,
                   role: int = ModelRoles.DisplayRole):

        if role == ModelRoles.DisplayRole and \
                orientation == QtCore.Qt.Orientation.Horizontal:

            return self.headers[section]

    def rowCount(self, parent: QtCore.QModelIndex = QtCore.QModelIndex()) -> int:
        """The number of rows in the model."""
        return len(self.item_list)

    def columnCount(self, parent: QtCore.QModelIndex = QtCore.QModelIndex()) -> int:
        """The number of columns in the model."""
        return len(self.headers)

    def data(self, index: QtCore.QModelIndex, role: int = ModelRoles.DisplayRole
             ) -> AllStdDataTypes | T | ContextMenuType:
        """Get the data at the specified index for the specified role."""
        if not self.item_list or not index.isValid():
            return None

        row = index.row()

        match role:
            case ModelRoles.DisplayRole:
                return str(self.item_list[row])
            case ModelRoles.PolicyObjRole:
                return self.item_list[row]
            case ModelRoles.ContextMenuRole:
                return ()
            case _:
                return None

    def flags(self, index: QtCore.QModelIndex = QtCore.QModelIndex()) -> QtCore.Qt.ItemFlag:
        """Get the flags for the specified index."""
        return QtCore.Qt.ItemFlag.ItemIsEnabled | \
            QtCore.Qt.ItemFlag.ItemIsSelectable | \
            QtCore.Qt.ItemFlag.ItemNeverHasChildren


class StringList(SEToolsTableModel[str]):

    """Convenience class for a list of strings using the table API."""

    headers = ["String"]
