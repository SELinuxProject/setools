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

import logging

from PyQt5.QtCore import Qt, QSortFilterProxyModel, QStringListModel, QThread
from PyQt5.QtGui import QPalette, QTextCursor
from PyQt5.QtWidgets import QCompleter, QHeaderView, QMessageBox, QProgressDialog, QScrollArea
from setools import DefaultQuery

from ..logtosignal import LogHandlerToSignal
from ..models import SEToolsListModel, invert_list_selection
from ..defaultmodel import DefaultTableModel
from ..widget import SEToolsWidget
from .queryupdater import QueryResultsUpdater


class DefaultQueryTab(SEToolsWidget, QScrollArea):

    """Default browser and query tab."""

    def __init__(self, parent, policy, perm_map):
        super(DefaultQueryTab, self).__init__(parent)
        self.log = logging.getLogger(__name__)
        self.policy = policy
        self.query = DefaultQuery(policy)
        self.setupUi()

    def __del__(self):
        self.thread.quit()
        self.thread.wait(5000)
        logging.getLogger("setools.defaultquery").removeHandler(self.handler)

    def setupUi(self):
        self.load_ui("defaultquery.ui")

        # set up results
        self.table_results_model = DefaultTableModel(self)
        self.sort_proxy = QSortFilterProxyModel(self)
        self.sort_proxy.setSourceModel(self.table_results_model)
        self.table_results.setModel(self.sort_proxy)
        self.table_results.sortByColumn(1, Qt.AscendingOrder)

        # populate class list
        self.class_model = SEToolsListModel(self)
        self.class_model.item_list = sorted(self.policy.classes())
        self.tclass.setModel(self.class_model)

        # set up processing thread
        self.thread = QThread()
        self.worker = QueryResultsUpdater(self.query, self.table_results_model)
        self.worker.moveToThread(self.thread)
        self.worker.raw_line.connect(self.raw_results.appendPlainText)
        self.worker.finished.connect(self.update_complete)
        self.worker.finished.connect(self.thread.quit)
        self.thread.started.connect(self.worker.update)

        # create a "busy, please wait" dialog
        self.busy = QProgressDialog(self)
        self.busy.setModal(True)
        self.busy.setRange(0, 0)
        self.busy.setMinimumDuration(0)
        self.busy.canceled.connect(self.thread.requestInterruption)
        self.busy.reset()

        # update busy dialog from query INFO logs
        self.handler = LogHandlerToSignal()
        self.handler.message.connect(self.busy.setLabelText)
        logging.getLogger("setools.defaultquery").addHandler(self.handler)

        # Ensure settings are consistent with the initial .ui state
        self.default_range_2.setEnabled(self.default_range.isChecked())
        self.notes.setHidden(not self.notes_expander.isChecked())

        # connect signals
        self.default_range.toggled.connect(self.default_range_2.setEnabled)
        self.clear_ruletypes.clicked.connect(self.clear_all_ruletypes)
        self.all_ruletypes.clicked.connect(self.set_all_ruletypes)
        self.tclass.selectionModel().selectionChanged.connect(self.set_tclass)
        self.invert_class.clicked.connect(self.invert_tclass_selection)
        self.buttonBox.clicked.connect(self.run)

    #
    # Ruletype criteria
    #
    def _set_ruletypes(self, value):
        self.default_user.setChecked(value)
        self.default_role.setChecked(value)
        self.default_type.setChecked(value)
        self.default_range.setChecked(value)

    def set_all_ruletypes(self):
        self._set_ruletypes(True)

    def clear_all_ruletypes(self):
        self._set_ruletypes(False)

    #
    # Class criteria
    #
    def set_tclass(self):
        selected_classes = []
        for index in self.tclass.selectionModel().selectedIndexes():
            selected_classes.append(self.class_model.data(index, Qt.UserRole))

        self.query.tclass = selected_classes

    def invert_tclass_selection(self):
        invert_list_selection(self.tclass.selectionModel())

    #
    # Results runner
    #
    def run(self, button):
        # right now there is only one button.
        rule_types = []

        for mode in [self.default_user, self.default_role, self.default_type, self.default_range]:
            if mode.isChecked():
                rule_types.append(mode.objectName())

        self.query.ruletype = rule_types
        self.query.default = self.default_2.currentData(Qt.DisplayRole)

        if self.default_range_2.isEnabled():
            self.query.default_range = self.default_range_2.currentData(Qt.DisplayRole)
        else:
            self.query.default_range = None

        # start processing
        self.busy.setLabelText("Processing query...")
        self.busy.show()
        self.raw_results.clear()
        self.thread.start()

    def update_complete(self, count):
        self.log.info("{0} default(s) found.".format(count))

        # update sizes/location of result displays
        if not self.busy.wasCanceled():
            self.busy.setLabelText("Resizing the result table's columns; GUI may be unresponsive")
            self.busy.repaint()
            self.table_results.resizeColumnsToContents()

        if not self.busy.wasCanceled():
            self.busy.setLabelText("Resizing the result table's rows; GUI may be unresponsive")
            self.busy.repaint()
            self.table_results.resizeRowsToContents()

        if not self.busy.wasCanceled():
            self.busy.setLabelText("Moving the raw result to top; GUI may be unresponsive")
            self.busy.repaint()
            self.raw_results.moveCursor(QTextCursor.Start)

        self.busy.reset()
