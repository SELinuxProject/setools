# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
from contextlib import suppress

from PyQt5 import QtCore
import setools

from .table import SEToolsTableModel

__all__ = ("DefaultTable",)


class DefaultTable(SEToolsTableModel[setools.Default]):

    """Table-based model for default_*."""

    headers = ["Rule Type", "Class", "Default", "Default Range"]

    def data(self, index: QtCore.QModelIndex, role: int = QtCore.Qt.ItemDataRole.DisplayRole):
        if not self.item_list or not index.isValid():
            return None

        row = index.row()
        col = index.column()
        item = self.item_list[row]

        match role:
            case QtCore.Qt.ItemDataRole.DisplayRole:
                match col:
                    case 0:
                        return item.ruletype.name
                    case 1:
                        return item.tclass.name
                    case 2:
                        return item.default.name
                    case 3:
                        with suppress(AttributeError):
                            return item.default_range.name  # type: ignore
                        return None

        return super().data(index, role)
