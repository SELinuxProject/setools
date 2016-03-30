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
import stat
from collections import defaultdict

from PyQt5.QtCore import Qt, QAbstractTableModel, QModelIndex


class GenfsconTableModel(QAbstractTableModel):

    """Table-based model for genfscons."""

    headers = defaultdict(str, {0: "FS Type", 1: "Path",
                                2: "File Type", 3: "Context"})

    _filetype_to_text = {
        0: "Any",
        stat.S_IFBLK: "Block",
        stat.S_IFCHR: "Character",
        stat.S_IFDIR: "Directory",
        stat.S_IFIFO: "Pipe (FIFO)",
        stat.S_IFREG: "Regular File",
        stat.S_IFLNK: "Symbolic Link",
        stat.S_IFSOCK: "Socket"}

    def __init__(self, parent):
        super(GenfsconTableModel, self).__init__(parent)
        self.resultlist = []

    def headerData(self, section, orientation, role):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self.headers[section]

    def columnCount(self, parent=QModelIndex()):
        return 4

    def rowCount(self, parent=QModelIndex()):
        if self.resultlist:
            return len(self.resultlist)
        else:
            return 0

    def data(self, index, role):
        if self.resultlist:
            row = index.row()
            col = index.column()
            rule = self.resultlist[row]

            if role == Qt.DisplayRole:
                if col == 0:
                    return rule.fs
                elif col == 1:
                    return rule.path
                elif col == 2:
                    return self._filetype_to_text[rule.filetype]
                elif col == 3:
                    return str(rule.context)

            elif role == Qt.UserRole:
                return rule
