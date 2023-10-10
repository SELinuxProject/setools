# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
import stat

from PyQt5 import QtCore
import setools

from .table import SEToolsTableModel

__all__ = ("GenfsconTable",)


class GenfsconTable(SEToolsTableModel[setools.Genfscon]):

    """Table-based model for genfscons."""

    headers = ["FS Type", "Path", "File Type", "Context"]

    _filetype_to_text = {
        0: "Any",
        stat.S_IFBLK: "Block",
        stat.S_IFCHR: "Character",
        stat.S_IFDIR: "Directory",
        stat.S_IFIFO: "Pipe (FIFO)",
        stat.S_IFREG: "Regular File",
        stat.S_IFLNK: "Symbolic Link",
        stat.S_IFSOCK: "Socket"}

    def data(self, index: QtCore.QModelIndex, role: int = QtCore.Qt.ItemDataRole.DisplayRole):
        if not self.item_list or not index.isValid():
            return None

        row = index.row()
        col = index.column()
        rule = self.item_list[row]

        match role:
            case QtCore.Qt.ItemDataRole.DisplayRole:
                match col:
                    case 0:
                        return rule.fs
                    case 1:
                        return rule.path
                    case 2:
                        return self._filetype_to_text[rule.filetype]
                    case 3:
                        return str(rule.context)

        return super().data(index, role)
