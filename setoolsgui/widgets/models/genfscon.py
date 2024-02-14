# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
import stat

from PyQt6 import QtCore
import setools

from .. import details
from .modelroles import ModelRoles
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

    def data(self, index: QtCore.QModelIndex, role: int = ModelRoles.DisplayRole):
        if not self.item_list or not index.isValid():
            return None

        row = index.row()
        col = index.column()
        rule = self.item_list[row]

        match role:
            case ModelRoles.DisplayRole:
                match col:
                    case 0:
                        return rule.fs
                    case 1:
                        return rule.path
                    case 2:
                        return self._filetype_to_text[rule.filetype]
                    case 3:
                        return str(rule.context)

            case ModelRoles.ContextMenuRole:
                if col == 3:
                    return details.context_detail_action(rule.context)

            case ModelRoles.WhatsThisRole:
                match col:
                    case 0:
                        column_whatsthis = \
                            """
                            <p>This is the filesystem type/name of the genfscon.</p>
                            """
                    case 1:
                        column_whatsthis = \
                            """
                            <p>This is the path of the genfscon.</p>
                            """
                    case 2:
                        column_whatsthis = \
                            """
                            <p>This is the file type of the genfscon.</p>
                            """
                    case 3:
                        column_whatsthis = \
                            """
                            <p>This is the context of the genfscon.</p>
                            """
                    case _:
                        column_whatsthis = ""

                return \
                    f"""
                    <b><p>Table Representation of Genfscons</p></b>

                    <p>Each part of the rule is represented as a column in the table.</p>

                    {column_whatsthis}
                    """

        return super().data(index, role)
