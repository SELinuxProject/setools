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
from ..details import objclass_detail, role_detail, type_or_attr_detail


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

                a = QtWidgets.QAction(f"Properties of {obj}")
                if isinstance(rule.target, Role):
                    a.triggered.connect(lambda x: role_detail(obj))
                else:
                    a.triggered.connect(lambda x: type_or_attr_detail(obj))
                return (a, )

            elif col == 3:
                try:
                    a = QtWidgets.QAction(f"Properties of {rule.tclass}")
                    a.triggered.connect(lambda x: objclass_detail(rule.tclass))
                    return (a, )
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
                    n_types = len(list(obj.types()))
                    if n_types == 0:
                        return f"{obj.name} is a role with no type associations."
                    elif n_types > 5:
                        return f"{obj.name} is a role associated with {n_types} types."
                    else:
                        return f"{obj.name} is a role associated with types: " \
                               f"{', '.join(t.name for t in obj.expand())}"

                elif isinstance(obj, Type):
                    return f"{obj.name} is a type."

                else:
                    n_types = len(obj)
                    if n_types == 0:
                        return f"{obj.name} is an empty type attribute."
                    elif n_types > 5:
                        return f"{obj.name} is a type attribute consisting of {n_types} types."
                    else:
                        return f"{obj.name} is a type attribute consisting of: " \
                               f"{', '.join(t.name for t in obj.expand())}"

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
