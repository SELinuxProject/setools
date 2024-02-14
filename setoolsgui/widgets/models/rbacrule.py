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

__all__ = ("RBACRuleTable",)


class RBACRuleTable(SEToolsTableModel[setools.AnyRBACRule]):

    """A table-based model for RBAC rules."""

    headers = ["Rule Type", "Source Role", "Target Role/Type", "Object Class", "Default Role"]

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
                        if rule.ruletype == setools.RBACRuletype.role_transition:
                            return rule.tclass.name
                    case 4:
                        if rule.ruletype == setools.RBACRuletype.role_transition:
                            return rule.default.name

                return None

            case ModelRoles.ContextMenuRole:
                match col:
                    case 1:
                        return (details.role_detail_action(rule.source), )
                    case 2:
                        if rule.ruletype == setools.RBACRuletype.role_transition:
                            assert isinstance(rule.target,
                                              setools.Type | setools.TypeAttribute), \
                                             "Invalid rule target, this is an SETools bug."
                            return (details.type_or_attr_detail_action(rule.target), )

                        assert isinstance(rule.target, setools.Role), \
                            "Invalid rule target, this is an SETools bug."
                        return (details.role_detail_action(rule.target), )
                    case 3:
                        if rule.ruletype == setools.RBACRuletype.role_transition:
                            return (details.objclass_detail_action(rule.tclass), )
                    case 4:
                        if rule.ruletype == setools.RBACRuletype.role_transition:
                            return (details.role_detail_action(rule.default), )

            case ModelRoles.ToolTipRole:
                match col:
                    case 1:
                        return details.role_tooltip(rule.source)
                    case 2:
                        if rule.ruletype == setools.RBACRuletype.role_transition:
                            assert isinstance(rule.target,
                                              setools.Type | setools.TypeAttribute), \
                                             "Invalid rule target, this is an SETools bug."
                            return details.type_or_attr_tooltip(rule.target)

                        assert isinstance(rule.target, setools.Role), \
                            "Invalid rule target, this is an SETools bug."
                        return details.role_tooltip(rule.target)
                    case 3:
                        return details.objclass_tooltip(rule.tclass)
                    case 4:
                        if rule.ruletype == setools.RBACRuletype.role_transition:
                            return details.role_tooltip(rule.default)

            case ModelRoles.WhatsThisRole:
                match col:
                    case 0:
                        column_whatsthis = f"<p>{rule.ruletype} is the type of the rule.</p>"
                    case 1:
                        column_whatsthis = \
                            f"<p>{rule.source} is the source role (subject) in the rule.</p>"
                    case 2:
                        if rule.ruletype == setools.RBACRuletype.role_transition:
                            column_whatsthis = \
                                f"""
                                <p>{rule.target} is the target type/attribute (object) in the rule.
                                </p>"""
                        else:
                            column_whatsthis = \
                                f"<p>{rule.target} is the target role (object) in the rule.</p>"
                    case 3:
                        if rule.ruletype == setools.RBACRuletype.role_transition:
                            column_whatsthis = \
                                f"<p>{rule.tclass} is the object class of the rule.</p>"
                        else:
                            column_whatsthis = \
                                f"""
                                <p>The object class column does not apply to {rule.ruletype} rules.
                                </p>"""
                    case 4:
                        if rule.ruletype == setools.RBACRuletype.role_transition:
                            column_whatsthis = \
                                f"<p>{rule.default} is the default role in the rule.<p>"
                        else:
                            column_whatsthis = \
                                f"""
                                <p>The default role column does not apply to {rule.ruletype} rules.
                                </p>"""
                    case _:
                        column_whatsthis = ""

                return \
                    f"""
                    <b><p>Table Representation of Role-based Access Control (RBAC) Rules</p></b>

                    <p>Each part of the rule is represented as a column in the table.</p>

                    {column_whatsthis}
                    """

        return super().data(index, role)
