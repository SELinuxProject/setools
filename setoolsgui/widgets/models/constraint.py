# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
from PyQt5 import QtCore
import setools

from .table import SEToolsTableModel

__all__ = ("ConstraintTable",)


class ConstraintTable(SEToolsTableModel[setools.Constraint]):

    """A table-based model for constraints."""

    headers = ["Rule Type", "Class", "Permissions", "Expression"]

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
                        return rule.ruletype.name
                    case 1:
                        return rule.tclass.name
                    case 2:
                        if rule.ruletype in (setools.ConstraintRuletype.constrain,
                                             setools.ConstraintRuletype.mlsconstrain):
                            return ", ".join(sorted(rule.perms))
                        else:
                            return None
                    case 3:
                        return str(rule.expression)

        return super().data(index, role)
