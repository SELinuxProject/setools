# Copyright 2016, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
import csv

from PyQt5 import QtCore, QtGui, QtWidgets

from .models import modelroles


class SEToolsTableView(QtWidgets.QTableView):

    """
    QTableView class extended for saving CSV files and context menu actions
    provided by the model.
    """

    def contextMenuEvent(self, event: QtGui.QContextMenuEvent) -> None:
        menu = QtWidgets.QMenu(self)
        menu.setAttribute(QtCore.Qt.WidgetAttribute.WA_DeleteOnClose)

        # Add any actions provided by the model.
        index = self.indexAt(event.pos())
        if index.isValid():
            for action in self.model().data(index, modelroles.ContextMenuRole):
                action.setParent(menu)
                menu.addAction(action)

            menu.addSeparator()

        # Add the save to CSV action
        save_csv_action = QtWidgets.QAction("Save table to CSV...", self)
        save_csv_action.triggered.connect(self.choose_csv_save_location)
        menu.addAction(save_csv_action)
        menu.popup(event.globalPos())

    def copy(self) -> None:
        datamodel = self.model()

        selected_text = []
        current_row = None
        current_col = None
        prev_row = None
        prev_col = None
        for index in sorted(self.selectionModel().selectedIndexes()):
            current_row = index.row()
            current_col = index.column()

            if prev_row is not None and current_row != prev_row:
                selected_text.append('\n')
            elif prev_col is not None and current_col != prev_col:
                selected_text.append('\t')

            selected_text.append(datamodel.data(index, QtCore.Qt.ItemDataRole.DisplayRole))

            prev_row = current_row
            prev_col = current_col

        QtWidgets.QApplication.clipboard().setText("".join(selected_text))

    def cut(self) -> None:
        self.copy()

    def choose_csv_save_location(self) -> None:
        filename = QtWidgets.QFileDialog.getSaveFileName(
            self,
            "Save to CSV",
            "table.csv",
            "Comma Separated Values Spreadsheet (*.csv);;"
            "All Files (*)")[0]

        if filename:
            self.save_csv(filename)

    def save_csv(self, filename: str) -> None:
        """Save the current table data to the specified CSV file."""

        datamodel = self.model()
        row_count = datamodel.rowCount()
        col_count = datamodel.columnCount()

        with open(filename, 'w') as fd:
            writer = csv.writer(fd, quoting=csv.QUOTE_MINIMAL)

            # write headers
            csv_row = []
            for col in range(col_count):
                csv_row.append(datamodel.headerData(col,
                                                    QtCore.Qt.Orientation.Horizontal,
                                                    QtCore.Qt.ItemDataRole.DisplayRole))

            writer.writerow(csv_row)

            # write data
            for row in range(row_count):
                csv_row = []

                for col in range(col_count):
                    index = datamodel.index(row, col)
                    csv_row.append(datamodel.data(index, QtCore.Qt.ItemDataRole.DisplayRole))

                writer.writerow(csv_row)
