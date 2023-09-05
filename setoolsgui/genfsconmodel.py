# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
import stat

from PyQt5.QtCore import Qt

from .models import SEToolsTableModel


class GenfsconTableModel(SEToolsTableModel):

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

    def data(self, index, role):
        if self.resultlist and index.isValid():
            row = index.row()
            col = index.column()
            rule = self.resultlist[row]

            if role == Qt.ItemDataRole.DisplayRole:
                if col == 0:
                    return rule.fs
                elif col == 1:
                    return rule.path
                elif col == 2:
                    return self._filetype_to_text[rule.filetype]
                elif col == 3:
                    return str(rule.context)

            elif role == Qt.ItemDataRole.UserRole:
                return rule
