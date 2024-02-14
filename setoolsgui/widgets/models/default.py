# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
from contextlib import suppress

from PyQt6 import QtCore
import setools

from .. import details
from .modelroles import ModelRoles
from .table import SEToolsTableModel

__all__ = ("DefaultTable",)


class DefaultTable(SEToolsTableModel[setools.Default]):

    """Table-based model for default_*."""

    headers = ["Rule Type", "Class", "Default", "Default Range"]

    def data(self, index: QtCore.QModelIndex, role: int = ModelRoles.DisplayRole):
        if not self.item_list or not index.isValid():
            return None

        row = index.row()
        col = index.column()
        item = self.item_list[row]

        match role:
            case ModelRoles.DisplayRole:
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

            case ModelRoles.ContextMenuRole:
                if col == 1:
                    return (details.objclass_detail_action(item.tclass),)

            case ModelRoles.WhatsThisRole:
                match col:
                    case 0:
                        column_whatsthis = "<p>This is the rule type.</p>"
                    case 1:
                        column_whatsthis = "<p>This is the object class of the rule.</p>"
                    case 2:
                        column_whatsthis = "<p>This is the value of the rule.</p>"
                    case 3:
                        column_whatsthis = \
                            """
                            <p>This is the range value of the rule.  This only applies to
                            default_range rules.</p>
                            """
                    case _:
                        column_whatsthis = ""

                return \
                    f"""
                    <b><p>Table Representation of default_* rules</p></b>

                    <p>Each part of the declaration is represented as a column in the table.</p>

                    {column_whatsthis}
                    """

        return super().data(index, role)
