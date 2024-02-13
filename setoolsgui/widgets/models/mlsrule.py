# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
from PyQt6 import QtCore
import setools

from .modelroles import ModelRoles
from .table import SEToolsTableModel
from .. import details

__all__ = ("MLSRuleTable",)


class MLSRuleTable(SEToolsTableModel[setools.MLSRule]):

    """A table-based model for MLS rules."""

    headers = ["Rule Type", "Source", "Target", "Object Class", "Default Range"]

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
                        return rule.source.name
                    case 2:
                        return rule.target.name
                    case 3:
                        return rule.tclass.name
                    case 4:
                        return str(rule.default)

            case ModelRoles.ContextMenuRole:
                match col:
                    case 1:
                        return (details.type_or_attr_detail_action(rule.source), )
                    case 2:
                        return (details.type_or_attr_detail_action(rule.target), )
                    case 3:
                        return (details.objclass_detail_action(rule.tclass), )

            case ModelRoles.ToolTipRole:
                match col:
                    case 1:
                        return details.type_or_attr_tooltip(rule.source)
                    case 2:
                        return details.type_or_attr_tooltip(rule.target)
                    case 3:
                        return details.objclass_tooltip(rule.tclass)

            case ModelRoles.WhatsThisRole:
                match col:
                    case 0:
                        column_whatsthis = \
                            f"""
                            <p>The Rule Type column is the type of the rule; it is one of:</p>
                            <ul>
                            {"".join(f"<li>{t.name}</li>" for t in setools.MLSRuletype)}
                            </ul>
                            """
                    case 1:
                        column_whatsthis = \
                            """
                            <p>This is the source type or type attribute (subject) in the rule.</p>
                            """
                    case 2:
                        column_whatsthis = \
                            """
                            <p>This is the target type or type attribute (object) in the rule.</p>
                            """
                    case 3:
                        column_whatsthis = "<p>This is the object class of the rule.</p>"
                    case 4:
                        column_whatsthis = \
                            """
                            <p>Default Range: This the the default range specified in the rule.</p>
                            """
                    case _:
                        column_whatsthis = ""

                return \
                    f"""
                    <b><p>Table Representation of Multi-Level Security Rules</p></b>

                    <p>Each part of the rule is represented as a column in the table.</p>

                    {column_whatsthis}
                    """

        return super().data(index, role)
