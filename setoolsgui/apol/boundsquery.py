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
from setools import BoundsQuery

from ..logtosignal import LogHandlerToSignal
from ..models import SEToolsListModel, invert_list_selection
from ..boundsmodel import BoundsTableModel
from ..widget import SEToolsWidget
from .queryupdater import QueryResultsUpdater


class BoundsQueryTab(SEToolsWidget, QScrollArea):

    """Bounds browser and query tab."""

    def __init__(self, parent, policy, perm_map):
        super(BoundsQueryTab, self).__init__(parent)
        self.log = logging.getLogger(__name__)
        self.policy = policy
        self.query = BoundsQuery(policy)
        self.setupUi()

    def __del__(self):
        self.thread.quit()
        self.thread.wait(5000)
        logging.getLogger("setools.boundsquery").removeHandler(self.handler)

    def setupUi(self):
        self.load_ui("boundsquery.ui")

        # set up results
        self.table_results_model = BoundsTableModel(self)
        self.sort_proxy = QSortFilterProxyModel(self)
        self.sort_proxy.setSourceModel(self.table_results_model)
        self.table_results.setModel(self.sort_proxy)
        self.table_results.sortByColumn(1, Qt.AscendingOrder)

        # setup indications of errors on level/range
        self.orig_palette = self.parent.palette()
        self.error_palette = self.parent.palette()
        self.error_palette.setColor(QPalette.Base, Qt.red)
        self.clear_parent_error()
        self.clear_child_error()

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
        logging.getLogger("setools.boundsquery").addHandler(self.handler)

        # Ensure settings are consistent with the initial .ui state
        self.notes.setHidden(not self.notes_expander.isChecked())

        # connect signals
        self.parent.textEdited.connect(self.clear_parent_error)
        self.parent.editingFinished.connect(self.set_parent)
        self.parent_regex.toggled.connect(self.set_parent_regex)
        self.child.textEdited.connect(self.clear_child_error)
        self.child.editingFinished.connect(self.set_child)
        self.child_regex.toggled.connect(self.set_child_regex)
        self.buttonBox.clicked.connect(self.run)

    #
    # Parent criteria
    #
    def clear_parent_error(self):
        self.parent.setToolTip("Match the parent type.")
        self.parent.setPalette(self.orig_palette)

    def set_parent(self):
        try:
            self.query.parent = self.parent.text()
        except Exception as ex:
            self.log.error("Type parent error: {0}".format(ex))
            self.parent.setToolTip("Error: " + str(ex))
            self.parent.setPalette(self.error_palette)

    def set_parent_regex(self, state):
        self.log.debug("Setting parent_regex {0}".format(state))
        self.query.parent_regex = state
        self.clear_parent_error()
        self.set_parent()

    #
    # Child criteria
    #
    def clear_child_error(self):
        self.child.setToolTip("Match the child type.")
        self.child.setPalette(self.orig_palette)

    def set_child(self):
        try:
            self.query.child = self.child.text()
        except Exception as ex:
            self.log.error("Type child error: {0}".format(ex))
            self.child.setToolTip("Error: " + str(ex))
            self.child.setPalette(self.error_palette)

    def set_child_regex(self, state):
        self.log.debug("Setting child_regex {0}".format(state))
        self.query.child_regex = state
        self.clear_child_error()
        self.set_child()

    #
    # Results runner
    #
    def run(self, button):
        # right now there is only one button.
        self.query.parent_regex = self.parent_regex.isChecked()
        self.query.child_regex = self.child_regex.isChecked()

        # start processing
        self.busy.setLabelText("Processing query...")
        self.busy.show()
        self.raw_results.clear()
        self.thread.start()

    def update_complete(self, count):
        self.log.info("{0} bound(s) found.".format(count))

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
