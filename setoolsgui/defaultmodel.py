# Copyright 2016, Tresys Technology, LLC
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

from PyQt5.QtCore import Qt

from .models import SEToolsTableModel


class DefaultTableModel(SEToolsTableModel):

    """Table-based model for default_*."""

    headers = defaultdict(str, {0: "Rule Type", 1: "Class", 2: "Default", 3: "Default Range"})

    def data(self, index, role):
        if self.resultlist and index.isValid():
            row = index.row()
            col = index.column()
            item = self.resultlist[row]

            if role == Qt.DisplayRole:
                if col == 0:
                    return item.ruletype
                elif col == 1:
                    return str(item.tclass)
                elif col == 2:
                    return str(item.default)
                elif col == 3:
                    try:
                        return str(item.default_range)
                    except AttributeError:
                        pass

            elif role == Qt.UserRole:
                return item
