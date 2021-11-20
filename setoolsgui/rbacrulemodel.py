# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
from PyQt5.QtCore import Qt
from setools.exception import RuleUseError

from .models import SEToolsTableModel


class RBACRuleTableModel(SEToolsTableModel):

    """A table-based model for RBAC rules."""

    headers = ["Rule Type", "Source", "Target", "Object Class", "Default Role"]

    def data(self, index, role):
        if self.resultlist and index.isValid():
            row = index.row()
            col = index.column()
            rule = self.resultlist[row]

            if role == Qt.DisplayRole:
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
                    # next most common: default
                    try:
                        return rule.default.name
                    except RuleUseError:
                        return None

            elif role == Qt.UserRole:
                return rule
