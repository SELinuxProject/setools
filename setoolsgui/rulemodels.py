# Copyright 2015, Tresys Technology, LLC
#
# This file is part of SETools.
#
# SETools is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation, either version 2.1 of
# the License, or (at your option) any later version.
#
# SETools is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with SETools.  If not, see
# <http://www.gnu.org/licenses/>.
#
from collections import defaultdict

from PyQt5.QtCore import Qt, QAbstractTableModel, QModelIndex
from setools.policyrep.exception import RuleNotConditional, RuleUseError


class RuleListModel(QAbstractTableModel):

    """Base class for rule list models."""

    headers = None

    def __init__(self, parent):
        super(RuleListModel, self).__init__(parent)
        self.resultlist = []

    def headerData(self, section, orientation, role):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self.headers[section]

    def columnCount(self, parent=QModelIndex()):
        return 5

    def rowCount(self, parent=QModelIndex()):
        if self.resultlist:
            return len(self.resultlist)
        else:
            return 0

    def data(self, index, role):
        raise NotImplementedError


class MLSRuleListModel(RuleListModel):

    """MLS rule model.  Represents rules as a column."""

    headers = defaultdict(None, {0: "Rule Type", 1: "Source", 2: "Target",
                                 3: "Object Class", 4: "Default Range"})

    def data(self, index, role):
        if self.resultlist:
            row = index.row()
            col = index.column()
            rule = self.resultlist[row]

            if role == Qt.DisplayRole:
                if col == 0:
                    return rule.ruletype
                elif col == 1:
                    return str(rule.source)
                elif col == 2:
                    return str(rule.target)
                elif col == 3:
                    return str(rule.tclass)
                elif col == 4:
                    return str(rule.default)

            elif role == Qt.UserRole:
                return rule


class RBACRuleListModel(RuleListModel):

    """RBAC rule model.  Represents rules as a column."""

    headers = defaultdict(None, {0: "Rule Type", 1: "Source", 2: "Target",
                                 3: "Object Class", 4: "Default Role"})

    def data(self, index, role):
        if self.resultlist:
            row = index.row()
            col = index.column()
            rule = self.resultlist[row]

            if role == Qt.DisplayRole:
                if col == 0:
                    return rule.ruletype
                elif col == 1:
                    return str(rule.source)
                elif col == 2:
                    return str(rule.target)
                elif col == 3:
                    try:
                        return str(rule.tclass)
                    except RuleUseError:
                        # role allow
                        return None
                elif col == 4:
                    # next most common: default
                    try:
                        return str(rule.default)
                    except RuleUseError:
                        return None

            elif role == Qt.UserRole:
                return rule


class TERuleListModel(RuleListModel):

    """Type Enforcement rule model.  Represents rules as a column."""

    headers = defaultdict(None, {0: "Rule Type", 1: "Source", 2: "Target",
                                 3: "Object Class", 4: "Permissions/Default Type",
                                 5: "Conditional Expression", 6: "Conditional Block"})

    def columnCount(self, parent=QModelIndex()):
        return 7

    def data(self, index, role):
        if self.resultlist:
            row = index.row()
            col = index.column()
            rule = self.resultlist[row]

            if role == Qt.DisplayRole:
                if col == 0:
                    return rule.ruletype
                elif col == 1:
                    return str(rule.source)
                elif col == 2:
                    return str(rule.target)
                elif col == 3:
                    return str(rule.tclass)
                elif col == 4:
                    try:
                        if rule.extended:
                            return "{0.xperm_type}: {0.perms:,}".format(rule)
                        else:
                            return ", ".join(sorted(rule.perms))
                    except RuleUseError:
                        return str(rule.default)
                elif col == 5:
                    try:
                        return str(rule.conditional)
                    except RuleNotConditional:
                        return None
                elif col == 6:
                    try:
                        return str(rule.conditional_block)
                    except RuleNotConditional:
                        return None

            elif role == Qt.UserRole:
                return rule
