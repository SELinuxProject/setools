# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#

import typing

from PyQt6 import QtCore
import setools

from .. import details
from .modelroles import ModelRoles
from .table import SEToolsTableModel

HAS_PERMS: typing.Final[tuple[setools.ConstraintRuletype, ...]] = (
    setools.ConstraintRuletype.constrain,
    setools.ConstraintRuletype.mlsconstrain)

__all__ = ("ConstraintTable",)


class ConstraintTable(SEToolsTableModel[setools.Constraint]):

    """A table-based model for constraints."""

    headers = ["Rule Type", "Class", "Permissions", "Expression"]

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
                        return rule.ruletype.name
                    case 1:
                        return rule.tclass.name
                    case 2:
                        if rule.ruletype in HAS_PERMS:
                            return ", ".join(sorted(rule.perms))
                        else:
                            return None
                    case 3:
                        return str(rule.expression)

            case ModelRoles.ContextMenuRole:
                if col == 2:
                    return details.objclass_detail_action(rule.tclass)

            case ModelRoles.WhatsThisRole:
                match col:
                    case 0:
                        column_whatsthis = \
                            """
                            <p>This is the type of constraint.</p>
                            """
                    case 1:
                        column_whatsthis = \
                            """
                            <p>This is the object class of the constraint.</p>
                            """
                    case 2:
                        if rule.ruletype in HAS_PERMS:
                            column_whatsthis = \
                                """
                                <p>These are the permissions of the constraint.</p>
                                """
                        else:
                            column_whatsthis = f"This column does not apply to {rule.ruletype}."
                    case 3:
                        column_whatsthis = \
                            """
                            <p>This expression of the constraint.</p>
                            """
                    case _:
                        column_whatsthis = ""

                return \
                    f"""
                    <b><p>Table Representation of Constraints</p></b>

                    <p>Each part of the rule is represented as a column in the table.</p>

                    {column_whatsthis}
                    """

        return super().data(index, role)
