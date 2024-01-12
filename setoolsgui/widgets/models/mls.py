# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
import typing

from PyQt6 import QtCore

from .table import SEToolsTableModel

__all__: typing.Final[tuple[str, ...]] = ("CategoryTable", "SensitivityTable")


class MLSComponentTable(SEToolsTableModel):

    """Table-based model for sensitivities and categories."""

    headers = ["Name", "Aliases"]

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
                        return item.name
                    case 1:
                        return ", ".join(sorted(a for a in item.aliases()))

        return super().data(index, role)


class CategoryTable(MLSComponentTable):

    """Table-based model for categories."""

    def data(self, index: QtCore.QModelIndex, role: int = QtCore.Qt.ItemDataRole.DisplayRole):
        if not self.item_list or not index.isValid():
            return None

        col = index.column()

        match role:
            case QtCore.Qt.ItemDataRole.WhatsThisRole:
                match col:
                    case 0:
                        column_whatsthis = "<p>This is the name of the category.</p>"
                    case 1:
                        column_whatsthis = "<p>These are the alias(es) of the category.</p>"
                    case _:
                        column_whatsthis = ""

                return \
                    f"""
                    <b><p>Table Representation of MLS Categories</p></b>

                    <p>Each part of the declaration is represented as a column in the table.</p>

                    {column_whatsthis}
                    """

        return super().data(index, role)


class SensitivityTable(MLSComponentTable):

    """Table-based model for sensitivities."""

    def data(self, index: QtCore.QModelIndex, role: int = QtCore.Qt.ItemDataRole.DisplayRole):
        if not self.item_list or not index.isValid():
            return None

        col = index.column()

        match role:
            case QtCore.Qt.ItemDataRole.WhatsThisRole:
                match col:
                    case 0:
                        column_whatsthis = "<p>This is the name of the sensitivity.</p>"
                    case 1:
                        column_whatsthis = "<p>These are the alias(es) of the sensitivity.</p>"
                    case _:
                        column_whatsthis = ""

                return \
                    f"""
                    <b><p>Table Representation of MLS Sensitivities</p></b>

                    <p>Each part of the declaration is represented as a column in the table.</p>

                    {column_whatsthis}
                    """

        return super().data(index, role)
