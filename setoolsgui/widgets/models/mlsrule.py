# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
from PyQt5 import QtCore, QtWidgets
from setools import MLSRuletype

from . import modelroles
from .table import SEToolsTableModel
from ..details import objclass_detail, type_or_attr_detail


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
                a = QtWidgets.QAction(f"Properties of {rule.source}")
                a.triggered.connect(lambda x: type_or_attr_detail(rule.source))
                return (a, )
            elif col == 2:
                a = QtWidgets.QAction(f"Properties of {rule.target}")
                a.triggered.connect(lambda x: type_or_attr_detail(rule.target))
                return (a, )
            elif col == 3:
                a = QtWidgets.QAction(f"Properties of {rule.tclass}")
                a.triggered.connect(lambda x: objclass_detail(rule.tclass))
                return (a, )

            return ()

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
