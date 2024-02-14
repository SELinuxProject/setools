# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
from contextlib import suppress

from PyQt6 import QtCore
import setools
from setools.exception import RuleNotConditional, RuleUseError

from .modelroles import ModelRoles
from .table import SEToolsTableModel
from .. import details

__all__ = ("TERuleTable",)


class TERuleTable(SEToolsTableModel[setools.AnyTERule]):

    """A table-based model for TE rules."""

    headers = ["Rule Type", "Source", "Target", "Object Class", "Permissions/Default Type",
               "Conditional Expression", "Conditional Branch"]

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
                        try:
                            if rule.extended:
                                return f"{rule.xperm_type}: {rule.perms:,}"  # type: ignore
                            else:
                                return ", ".join(sorted(rule.perms))  # type: ignore
                        except RuleUseError:
                            return rule.default.name
                    case 5:
                        with suppress(RuleNotConditional):
                            return str(rule.conditional)
                    case 6:
                        with suppress(RuleNotConditional):
                            return str(rule.conditional_block)

                return None

            case ModelRoles.ContextMenuRole:
                match col:
                    case 1:
                        return (details.type_or_attr_detail_action(rule.source), )
                    case 2:
                        return (details.type_or_attr_detail_action(rule.target), )
                    case 3:
                        return (details.objclass_detail_action(rule.tclass), )
                    case 4:
                        with suppress(RuleUseError):
                            return (details.type_detail_action(rule.default), )

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
                            {"".join(f"<li>{t.name}</li>" for t in setools.TERuletype)}
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
                            <p>Permissions/Default Type: The value of this depends on the rule
                               type:</p>
                            <ul>
                            <li>Allow and allow-like rules: These are the permissions set in the
                                rule.</li>
                            <li>type_* rules: This the the default type specified in the rule.</li>
                            </ul>
                            </li>
                            """
                    case 5:
                        column_whatsthis = \
                            """
                            <p>This is the conditional expression that enables/disables
                            this rule.  If this is blank, the rule is unconditional.</p>
                            """
                    case 6:
                        column_whatsthis = \
                            """
                            <p>This contains the conditional branch that that rule resides in.
                            "True" means the rule is enabled when the conditional expression is
                            true; also known as the "if" block.  "False" means the rule is enabled
                            when the conditional expression is false; also known as the "else"
                            block.  If this is blank, the rule is unconditional.</p>
                            """
                    case _:
                        column_whatsthis = ""

                return \
                    f"""
                    <b><p>Table Representation of Type Enforcement Rules</p></b>

                    <p>Each part of the rule is represented as a column in the table.</p>

                    {column_whatsthis}
                    """

        return super().data(index, role)
