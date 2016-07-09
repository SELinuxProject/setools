# Copyright 2016, Chris PeBenito <pebenito@ieee.org>
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

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QKeySequence
from PyQt5.QtWidgets import QApplication, QTableView


class SEToolsTableView(QTableView):

    """QTableView class extended for SETools use."""

    def event(self, e):
        if e == QKeySequence.Copy or e == QKeySequence.Cut:
            datamodel = self.model()

            selected_text = ""
            current_row = None
            current_col = None
            prev_row = None
            prev_col = None
            for index in sorted(self.selectionModel().selectedIndexes()):
                current_row = index.row()
                current_col = index.column()

                if prev_row is not None and current_row != prev_row:
                    selected_text += '\n'
                elif prev_col is not None and current_col != prev_col:
                    selected_text += '\t'

                selected_text += datamodel.data(index, Qt.DisplayRole)

                prev_row = current_row
                prev_col = current_col

            QApplication.clipboard().setText(selected_text)
            return True

        else:
            return super(SEToolsTableView, self).event(e)
