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


class SEToolsTableModel(QtCore.QAbstractTableModel, typing.Generic[T], metaclass=MetaclassFix):

    """Base class for SETools table models, modeling a list in a tabular form."""

    headers: typing.List[str] = []

    def __init__(self, parent: QtCore.QObject | None = None):
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

    def headerData(self, section: int, orientation: QtCore.Qt.Orientation,
                   role: int = QtCore.Qt.ItemDataRole.DisplayRole):

        if role == QtCore.Qt.ItemDataRole.DisplayRole and \
                orientation == QtCore.Qt.Orientation.Horizontal:

            return self.headers[section]

    def rowCount(self, parent: QtCore.QModelIndex = QtCore.QModelIndex()) -> int:
        """The number of rows in the model."""
        return len(self.item_list)

    def columnCount(self, parent: QtCore.QModelIndex = QtCore.QModelIndex()) -> int:
        """The number of columns in the model."""
        return len(self.headers)

    def data(self, index: QtCore.QModelIndex, role: int = QtCore.Qt.ItemDataRole.DisplayRole):
        """Get the data at the specified index for the specified role."""
        if not self.item_list or not index.isValid():
            return None

        row = index.row()

        match role:
            case QtCore.Qt.ItemDataRole.DisplayRole:
                raise NotImplementedError
            case modelroles.PolicyObjRole:
                return self.item_list[row]
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
