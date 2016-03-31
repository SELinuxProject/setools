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
from setools import DomainTransitionAnalysis

from ..logtosignal import LogHandlerToSignal
from .excludetypes import ExcludeTypes
from ..widget import SEToolsWidget


class DomainTransitionAnalysisTab(SEToolsWidget, QScrollArea):

    """A domain transition analysis tab."""

    def __init__(self, parent, policy, perm_map):
        super(DomainTransitionAnalysisTab, self).__init__(parent)
        self.log = logging.getLogger(__name__)
        self.policy = policy
        self.query = DomainTransitionAnalysis(policy)
        self.query.source = None
        self.query.target = None
        self.setupUi()

    def __del__(self):
        self.thread.quit()
        self.thread.wait(5000)
        logging.getLogger("setools.dta").removeHandler(self.handler)

    def setupUi(self):
        self.log.debug("Initializing UI.")
        self.load_ui("dta.ui")

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

        # update busy dialog from DTA INFO logs
        self.handler = LogHandlerToSignal()
        self.handler.message.connect(self.busy.setLabelText)
        logging.getLogger("setools.dta").addHandler(self.handler)

        # Ensure settings are consistent with the initial .ui state
        self.max_path_length.setEnabled(self.all_paths.isChecked())
        self.source.setEnabled(not self.flows_in.isChecked())
        self.target.setEnabled(not self.flows_out.isChecked())
        self.criteria_frame.setHidden(not self.criteria_expander.isChecked())
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
        self.reverse.stateChanged.connect(self.reverse_toggled)
        self.exclude_types.clicked.connect(self.choose_excluded_types)

    #
    # Analysis mode
    #
    def all_paths_toggled(self, value):
        self.clear_source_error()
        self.clear_target_error()
        self.max_path_length.setEnabled(value)

    def flows_in_toggled(self, value):
        self.clear_source_error()
        self.clear_target_error()
        self.source.setEnabled(not value)
        self.reverse.setEnabled(not value)

        if value:
            self.reverse_old = self.reverse.isChecked()
            self.reverse.setChecked(True)
        else:
            self.reverse.setChecked(self.reverse_old)

    def flows_out_toggled(self, value):
        self.clear_source_error()
        self.clear_target_error()
        self.target.setEnabled(not value)
        self.reverse.setEnabled(not value)

        if value:
            self.reverse_old = self.reverse.isChecked()
            self.reverse.setChecked(False)
        else:
            self.reverse.setChecked(self.reverse_old)

    #
    # Source criteria
    #
    def set_source_error(self, error_text):
        self.log.error("Source domain error: {0}".format(error_text))
        self.source.setToolTip("Error: {0}".format(error_text))
        self.source.setPalette(self.error_palette)

    def clear_source_error(self):
        self.source.setToolTip("The source domain of the analysis.")
        self.source.setPalette(self.orig_palette)

    def set_source(self):
        try:
            # look up the type here, so invalid types can be caught immediately
            text = self.source.text()
            if text:
                self.query.source = self.policy.lookup_type(text)
            else:
                self.query.source = None
        except Exception as ex:
            self.set_source_error(ex)

    #
    # Target criteria
    #
    def set_target_error(self, error_text):
        self.log.error("Target domain error: {0}".format(error_text))
        self.target.setToolTip("Error: {0}".format(error_text))
        self.target.setPalette(self.error_palette)

    def clear_target_error(self):
        self.target.setToolTip("The target domain of the analysis.")
        self.target.setPalette(self.orig_palette)

    def set_target(self):
        try:
            # look up the type here, so invalid types can be caught immediately
            text = self.target.text()
            if text:
                self.query.target = self.policy.lookup_type(text)
            else:
                self.query.target = None
        except Exception as ex:
            self.set_target_error(ex)

    #
    # Options
    #
    def choose_excluded_types(self):
        chooser = ExcludeTypes(self, self.policy)
        chooser.show()

    def reverse_toggled(self, value):
        self.query.reverse = value

    #
    # Results runner
    #

    def run(self, button):
        # right now there is only one button.
        fail = False
        if self.source.isEnabled() and not self.query.source:
            self.set_source_error("A source domain is required")
            fail = True

        if self.target.isEnabled() and not self.query.target:
            self.set_target_error("A target domain is required.")
            fail = True

        if fail:
            return

        for mode in [self.all_paths, self.all_shortest_paths, self.flows_in, self.flows_out]:
            if mode.isChecked():
                break

        self.query.mode = mode.objectName()
        self.query.max_path_len = self.max_path_length.value()
        self.query.limit = self.limit_paths.value()

        # start processing
        self.busy.setLabelText("Processing query...")
        self.busy.show()
        self.raw_results.clear()
        self.thread.start()

    def update_complete(self):
        if not self.busy.wasCanceled():
            self.busy.setLabelText("Moving the raw result to top; GUI may be unresponsive")
            self.busy.repaint()
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
        self.log = logging.getLogger(__name__)

    def update(self):
        """Run the query and update results."""

        assert self.query.limit, "Code doesn't currently handle unlimited (limit=0) paths."
        if self.query.mode == "all_paths":
            self.transitive(self.query.all_paths(self.query.source, self.query.target,
                                                 self.query.max_path_len))
        elif self.query.mode == "all_shortest_paths":
            self.transitive(self.query.all_shortest_paths(self.query.source, self.query.target))
        elif self.query.mode == "flows_out":
            self.direct(self.query.transitions(self.query.source))
        else:  # flows_in
            self.direct(self.query.transitions(self.query.target))

        self.finished.emit()

    def print_transition(self, trans):
        """Raw rendering of a domain transition."""

        if trans.transition:
            self.raw_line.emit("Domain transition rule(s):")
            for t in trans.transition:
                self.raw_line.emit(str(t))

            if trans.setexec:
                self.raw_line.emit("\nSet execution context rule(s):")
                for s in trans.setexec:
                    self.raw_line.emit(str(s))

            for entrypoint in trans.entrypoints:
                self.raw_line.emit("\nEntrypoint {0}:".format(entrypoint.name))

                self.raw_line.emit("\tDomain entrypoint rule(s):")
                for e in entrypoint.entrypoint:
                    self.raw_line.emit("\t{0}".format(e))

                self.raw_line.emit("\n\tFile execute rule(s):")
                for e in entrypoint.execute:
                    self.raw_line.emit("\t{0}".format(e))

                if entrypoint.type_transition:
                    self.raw_line.emit("\n\tType transition rule(s):")
                    for t in entrypoint.type_transition:
                        self.raw_line.emit("\t{0}".format(t))

                self.raw_line.emit("")

        if trans.dyntransition:
            self.raw_line.emit("Dynamic transition rule(s):")
            for d in trans.dyntransition:
                self.raw_line.emit(str(d))

            self.raw_line.emit("\nSet current process context rule(s):")
            for s in trans.setcurrent:
                self.raw_line.emit(str(s))

            self.raw_line.emit("")

        self.raw_line.emit("")

    def transitive(self, paths):
        i = 0
        for i, path in enumerate(paths, start=1):
            self.raw_line.emit("Domain transition path {0}:".format(i))

            for stepnum, step in enumerate(path, start=1):

                self.raw_line.emit("Step {0}: {1} -> {2}\n".format(stepnum, step.source,
                                                                   step.target))
                self.print_transition(step)

            if QThread.currentThread().isInterruptionRequested() or (i >= self.query.limit):
                break
            else:
                QThread.yieldCurrentThread()

        self.raw_line.emit("{0} domain transition path(s) found.".format(i))
        self.log.info("{0} domain transition path(s) found.".format(i))

    def direct(self, transitions):
        i = 0
        for i, step in enumerate(transitions, start=1):
            self.raw_line.emit("Transition {0}: {1} -> {2}\n".format(i, step.source, step.target))
            self.print_transition(step)

            if QThread.currentThread().isInterruptionRequested() or (i >= self.query.limit):
                break
            else:
                QThread.yieldCurrentThread()

        self.raw_line.emit("{0} domain transition(s) found.".format(i))
        self.log.info("{0} domain transition(s) found.".format(i))
