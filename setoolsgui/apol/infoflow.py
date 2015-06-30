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

import logging

from PyQt5.QtCore import pyqtSignal, Qt, QObject, QStringListModel, QThread
from PyQt5.QtGui import QPalette, QTextCursor
from PyQt5.QtWidgets import QCompleter, QHeaderView, QMessageBox, QProgressDialog, QScrollArea
from setools import InfoFlowAnalysis

from ..widget import SEToolsWidget


class InfoFlowAnalysisTab(SEToolsWidget, QScrollArea):

    """
    An information flow analysis tab.

    Qt signals:
    update_results      Signal child worker thread to run the analysis.
    """

    update_results = pyqtSignal(str, str, str, int, int)

    def __init__(self, parent, policy, perm_map):
        super(InfoFlowAnalysisTab, self).__init__(parent)
        self.log = logging.getLogger(self.__class__.__name__)
        self.policy = policy
        self.query = InfoFlowAnalysis(policy, perm_map)
        self.setupUi()

    def __del__(self):
        self.thread.quit()
        self.thread.wait(5000)
        self.log.debug("Thread successfully finished: %s", self.thread.isFinished())

    def setupUi(self):
        self.log.debug("Initializing UI.")
        self.load_ui("infoflow.ui")

        # set up source/target autocompletion
        type_completion_list = [str(t) for t in self.policy.types()]
        type_completer_model = QStringListModel(self)
        type_completer_model.setStringList(sorted(type_completion_list))
        self.type_completion = QCompleter()
        self.type_completion.setModel(type_completer_model)
        self.source.setCompleter(self.type_completion)
        self.target.setCompleter(self.type_completion)

        # setup indications of errors on source/target/default
        self.orig_palette = self.source.palette()
        self.error_palette = self.source.palette()
        self.error_palette.setColor(QPalette.Base, Qt.red)
        self.clear_source_error()
        self.clear_target_error()

        # set up processing thread
        self.thread = QThread()
        self.worker = ResultsUpdater(self.query)
        self.worker.raw_line.connect(self.raw_results.appendPlainText)
        self.worker.finished.connect(self.update_complete)
        self.worker.moveToThread(self.thread)
        self.update_results.connect(self.worker.update)
        self.thread.start()

        # create a "busy, please wait" dialog
        self.busy = QProgressDialog(self)
        self.busy.setModal(True)
        self.busy.setLabelText("Processing analysis...")
        self.busy.setRange(0, 0)
        self.busy.setMinimumDuration(0)
        self.busy.canceled.connect(self.thread.requestInterruption)

        # Ensure settings are consistent with the initial .ui state
        self.max_path_length.setEnabled(self.all_paths.isChecked())
        self.source.setEnabled(not self.flows_in.isChecked())
        self.target.setEnabled(not self.flows_out.isChecked())
        self.criteria_frame.setHidden(not self.criteria_expander.isChecked())
        self.results_frame.setHidden(not self.results_expander.isChecked())
        self.notes.setHidden(not self.notes_expander.isChecked())

        # connect signals
        self.buttonBox.clicked.connect(self.run)
        self.source.textEdited.connect(self.clear_source_error)
        self.source.editingFinished.connect(self.set_source)
        self.target.textEdited.connect(self.clear_target_error)
        self.target.editingFinished.connect(self.set_target)
        self.all_paths.toggled.connect(self.all_paths_toggled)
        self.flows_in.toggled.connect(self.flows_in_toggled)
        self.flows_out.toggled.connect(self.flows_out_toggled)

    #
    # Analysis mode
    #
    def all_paths_toggled(self, value):
        self.max_path_length.setEnabled(value)

    def flows_in_toggled(self, value):
        self.source.setEnabled(not value)

    def flows_out_toggled(self, value):
        self.target.setEnabled(not value)

    #
    # Source criteria
    #

    def clear_source_error(self):
        self.source.setToolTip("The target type of the analysis.")
        self.source.setPalette(self.orig_palette)

    def set_source(self):
        try:
            # look up the type here, so invalid types can be caught immediately
            text = self.source.text()
            if text:
                self.query.source = self.policy.lookup_type(text)
        except Exception as ex:
            self.source.setToolTip("Error: " + str(ex))
            self.source.setPalette(self.error_palette)

    #
    # Target criteria
    #

    def clear_target_error(self):
        self.target.setToolTip("The source type of the analysis.")
        self.target.setPalette(self.orig_palette)

    def set_target(self):
        try:
            # look up the type here, so invalid types can be caught immediately
            text = self.target.text()
            if text:
                self.query.target = self.policy.lookup_type(text)
        except Exception as ex:
            self.target.setToolTip("Error: " + str(ex))
            self.target.setPalette(self.error_palette)

    #
    # Results runner
    #

    def run(self, button):
        # right now there is only one button.
        for mode in [self.all_paths, self.all_shortest_paths, self.flows_in, self.flows_out]:
            if mode.isChecked():
                break

        # start processing
        self.busy.show()
        self.raw_results.clear()
        self.update_results.emit(mode.objectName(),
                                 self.source.text(),
                                 self.target.text(),
                                 self.max_path_length.value(),
                                 self.limit_paths.value())

    def update_complete(self):
        # update location of result display
        self.raw_results.moveCursor(QTextCursor.Start)

        self.busy.reset()


class ResultsUpdater(QObject):

    """
    Thread for processing queries and updating result widgets.

    Parameters:
    query       The query object
    model       The model for the results

    Qt signals:
    finished    The update has completed.
    raw_line    (str) A string to be appended to the raw results.
    """

    finished = pyqtSignal()
    raw_line = pyqtSignal(str)

    def __init__(self, query):
        super(ResultsUpdater, self).__init__()
        self.query = query

    def update(self, mode, source, target, max_path_len, limit):
        """Run the query and update results."""

        if mode == "all_paths":
            self.transitive(self.query.all_paths(source, target, max_path_len), limit)
        elif mode == "all_shortest_paths":
            self.transitive(self.query.all_shortest_paths(source, target), limit)
        elif mode == "flows_out":
            self.direct(self.query.infoflows(source), limit)
        else:  # flows_in
            pass

        self.finished.emit()

    def transitive(self, paths, limit):
        pathnum = 0
        for pathnum, path in enumerate(paths, start=1):
            self.raw_line.emit("Flow {0}:".format(pathnum))
            for stepnum, step in enumerate(path, start=1):
                self.raw_line.emit("  Step {0}: {1} -> {2}".format(stepnum,
                                                                   step.source,
                                                                   step.target))

                for rule in sorted(step.rules):
                    self.raw_line.emit("    {0}".format(rule))

                self.raw_line.emit("")

            if QThread.currentThread().isInterruptionRequested() or (limit and pathnum >= limit):
                break
            else:
                QThread.yieldCurrentThread()

            self.raw_line.emit("")

        self.raw_line.emit("{0} information flow path(s) found.\n".format(pathnum))

    def direct(self, flows, limit):
        flownum = 0
        for flownum, flow in enumerate(flows, start=1):
            self.raw_line.emit("Flow {0}: {1} -> {2}".format(flownum, flow.source, flow.target))
            for rule in sorted(flow.rules):
                self.raw_line.emit("    {0}".format(rule))

            self.raw_line.emit("")

            if QThread.currentThread().isInterruptionRequested() or (limit and flownum >= limit):
                break
            else:
                QThread.yieldCurrentThread()

        self.raw_line.emit("{0} information flow(s) found.\n".format(flownum))
