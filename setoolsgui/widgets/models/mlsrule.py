# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
from PyQt5 import QtCore, QtWidgets
from setools import MLSRuletype

from . import modelroles
from .table import SEToolsTableModel
from .. import details


class MLSRuleTableModel(SEToolsTableModel):

    """A table-based model for MLS rules."""

    headers = ["Rule Type", "Source", "Target", "Object Class", "Default Range"]

    def data(self, index: QtCore.QModelIndex, role: int = QtCore.Qt.ItemDataRole.DisplayRole):
        if not self.item_list or not index.isValid():
            return None

        row = index.row()
        col = index.column()
        rule = self.item_list[row]

        if role == QtCore.Qt.ItemDataRole.DisplayRole:
            if col == 0:
                return rule.ruletype.name
            elif col == 1:
                return rule.source.name
            elif col == 2:
                return rule.target.name
            elif col == 3:
                return rule.tclass.name
            elif col == 4:
                return str(rule.default)

        elif role == modelroles.ContextMenuRole:
            if col == 1:
                return (details.type_or_attr_detail_action(rule.source), )
            elif col == 2:
                return (details.type_or_attr_detail_action(rule.target), )
            elif col == 3:
                return (details.objclass_detail_action(rule.tclass), )

            return ()

        elif role == QtCore.Qt.ItemDataRole.ToolTipRole:
            if col in (1, 2):
                if col == 1:
                    return details.type_or_attr_tooltip(rule.source)
                else:
                    return details.type_or_attr_tooltip(rule.target)
            elif col == 3:
                return details.objclass_tooltip(rule.tclass)

            return None

        elif role == QtCore.Qt.ItemDataRole.WhatsThisRole:
            if col == 0:
                column_whatsthis = \
                    f"""
                    <p>The Rule Type column is the type of the rule; it is one of:</p>
                    <ul>
                    {"".join(f"<li>{t.name}</li>" for t in MLSRuletype)}
                    </ul>
                    """
            elif col == 1:
                column_whatsthis = \
                    "<p>This is the source type or type attribute (subject) in the rule.</p>"
            elif col == 2:
                column_whatsthis = \
                    "<p>This is the target type or type attribute (object) in the rule.</p>"
            elif col == 3:
                column_whatsthis = "<p>This is the object class of the rule.</p>"
            elif col == 4:
                column_whatsthis = \
                    """<p>Default Range: This the the default range specified in the rule.</p>"""
            return \
                f"""
                <b><p>Table Representation of Multi-Level Security Rules</p></b>

                <p>Each part of the rule is represented as a column in the table.</p>

                {column_whatsthis}
                """

        return super().data(index, role)
