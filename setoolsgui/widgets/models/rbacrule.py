# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
from PyQt5 import QtCore, QtWidgets
from setools import AnyRBACRule, Role, Type
from setools.exception import RuleUseError

from . import modelroles
from .table import SEToolsTableModel
from .. import details


class RBACRuleTableModel(SEToolsTableModel[AnyRBACRule]):

    """A table-based model for RBAC rules."""

    headers = ["Rule Type", "Source Role", "Target Role/Type", "Object Class", "Default Role"]

    def data(self, index, role):
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
                try:
                    return rule.tclass.name
                except RuleUseError:
                    # role allow
                    return None
            elif col == 4:
                try:
                    return rule.default.name
                except RuleUseError:
                    # role allow
                    return None

        elif role == modelroles.ContextMenuRole:
            if col in (1, 2, 4):
                if col == 1:
                    obj = rule.source
                elif col == 2:
                    obj = rule.target
                else:
                    try:
                        obj = rule.default
                    except RuleUseError:
                        return ()

                if isinstance(obj, Role):
                    return (details.role_detail_action(obj), )
                else:
                    return (details.type_or_attr_detail_action(obj), )

            elif col == 3:
                try:
                    return (details.objclass_detail_action(rule.tclass), )
                except RuleUseError:
                    pass

            return ()

        elif role == QtCore.Qt.ItemDataRole.ToolTipRole:
            if col in (1, 2):
                if col == 1:
                    obj = rule.source
                elif col == 2:
                    obj = rule.target
                else:
                    try:
                        obj = rule.default
                    except RuleUseError:
                        return None

                if isinstance(obj, Role):
                    return details.role_tooltip(obj)
                else:
                    return details.type_or_attr_tooltip(obj)
            elif col == 3:
                return details.objclass_tooltip(rule.tclass)

            return None

        elif role == QtCore.Qt.ItemDataRole.WhatsThisRole:
            if col == 0:
                column_whatsthis = f"<p>{rule.ruletype} is the type of the rule.</p>"
            elif col == 1:
                column_whatsthis = \
                    f"<p>{rule.source} is the source role (subject) in the rule.</p>"
            elif col == 2:
                if isinstance(rule.target, Role):
                    column_whatsthis = \
                        f"<p>{rule.target} is the target role (object) in the rule.</p>"
                else:
                    column_whatsthis = \
                        f"<p>{rule.target} is the target type/attribute (object) in the rule.</p>"
            elif col == 3:
                try:
                    column_whatsthis = f"<p>{rule.tclass} is the object class of the rule.</p>"
                except RuleUseError:
                    column_whatsthis = \
                        f"<p>The object class column does not apply to {rule.ruletype} rules.</p>"
            elif col == 4:
                try:
                    column_whatsthis = f"<p>{rule.default} is the default role in the rule.<p>"
                except RuleUseError:
                    column_whatsthis = \
                       f"<p>The default role column does not apply to {rule.ruletype} rules.</p>"

            return \
                f"""
                <b><p>Table Representation of Role-based Access Control (RBAC) Rules</p></b>

                <p>Each part of the rule is represented as a column in the table.</p>

                {column_whatsthis}
                """

        return super().data(index, role)
