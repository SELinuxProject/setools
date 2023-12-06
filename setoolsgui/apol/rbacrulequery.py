# Copyright 2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#

import logging
from contextlib import suppress

from PyQt5.QtCore import Qt, QSortFilterProxyModel, QStringListModel, QThread
from PyQt5.QtGui import QPalette, QTextCursor
from PyQt5.QtWidgets import QCompleter, QHeaderView, QMessageBox, QProgressDialog
from setools import RBACRuleQuery

from ..logtosignal import LogHandlerToSignal
from ..models import SEToolsListModel, invert_list_selection
from ..rbacrulemodel import RBACRuleTableModel
from .analysistab import AnalysisSection, AnalysisTab
from .exception import TabFieldError
from .queryupdater import QueryResultsUpdater
from .workspace import load_checkboxes, load_lineedits, load_listviews, load_textedits, \
    save_checkboxes, save_lineedits, save_listviews, save_textedits


class RBACRuleQueryTab(AnalysisTab):

    """A RBAC rule query."""

    section = AnalysisSection.Rules
    tab_title = "RBAC Rules"
    mlsonly = False

    def __init__(self, parent, policy, perm_map):
        super(RBACRuleQueryTab, self).__init__(parent)
        self.log = logging.getLogger(__name__)
        self.policy = policy
        self.query = RBACRuleQuery(policy)
        self.setupUi()

    def __del__(self):
        with suppress(RuntimeError):
            self.thread.quit()
            self.thread.wait(5000)

        logging.getLogger("setools.rbacrulequery").removeHandler(self.handler)

    def setupUi(self):
        self.load_ui("apol/rbacrulequery.ui")

        # set up role autocompletion (source, default)
        role_completion_list = [str(r) for r in self.policy.roles()]
        role_completer_model = QStringListModel(self)
        role_completer_model.setStringList(sorted(role_completion_list))
        self.role_completion = QCompleter()
        self.role_completion.setModel(role_completer_model)
        self.source.setCompleter(self.role_completion)
        self.default_role.setCompleter(self.role_completion)

        # set up role/type autocompletion (target)
        roletype_completion_list = [str(r) for r in self.policy.roles()]
        # roletype_completion_list.extend(str(a) for a in self.policy.roleattributes())
        roletype_completion_list.extend(str(t) for t in self.policy.types())
        roletype_completion_list.extend(str(a) for a in self.policy.typeattributes())
        roletype_completer_model = QStringListModel(self)
        roletype_completer_model.setStringList(sorted(roletype_completion_list))
        self.roletype_completion = QCompleter()
        self.roletype_completion.setModel(roletype_completer_model)
        self.target.setCompleter(self.roletype_completion)

        # setup indications of errors on source/target/default
        self.errors = set()
        self.orig_palette = self.source.palette()
        self.error_palette = self.source.palette()
        self.error_palette.setColor(QPalette.ColorRole.Base, Qt.GlobalColor.red)
        self.clear_source_error()
        self.clear_target_error()
        self.clear_default_error()

        # populate class list
        self.class_model = SEToolsListModel(self)
        self.class_model.item_list = sorted(self.policy.classes())
        self.tclass.setModel(self.class_model)

        # set up results
        self.table_results_model = RBACRuleTableModel(self)
        self.sort_proxy = QSortFilterProxyModel(self)
        self.sort_proxy.setSourceModel(self.table_results_model)
        self.table_results.setModel(self.sort_proxy)
        self.table_results.sortByColumn(0, Qt.SortOrder.AscendingOrder)

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
        logging.getLogger("setools.rbacrulequery").addHandler(self.handler)

        # Ensure settings are consistent with the initial .ui state
        self.set_source_regex(self.source_regex.isChecked())
        self.set_target_regex(self.target_regex.isChecked())
        self.set_default_regex(self.default_regex.isChecked())
        self.criteria_frame.setHidden(not self.criteria_expander.isChecked())
        self.notes.setHidden(not self.notes_expander.isChecked())

        # connect signals
        self.buttonBox.clicked.connect(self.run)
        self.clear_ruletypes.clicked.connect(self.clear_all_ruletypes)
        self.all_ruletypes.clicked.connect(self.set_all_ruletypes)
        self.source.textEdited.connect(self.clear_source_error)
        self.source.editingFinished.connect(self.set_source)
        self.source_regex.toggled.connect(self.set_source_regex)
        self.target.textEdited.connect(self.clear_target_error)
        self.target.editingFinished.connect(self.set_target)
        self.target_regex.toggled.connect(self.set_target_regex)
        self.tclass.selectionModel().selectionChanged.connect(self.set_tclass)
        self.invert_class.clicked.connect(self.invert_tclass_selection)
        self.default_role.textEdited.connect(self.clear_default_error)
        self.default_role.editingFinished.connect(self.set_default_role)
        self.default_regex.toggled.connect(self.set_default_regex)

    #
    # Ruletype criteria
    #

    def _set_ruletypes(self, value):
        self.allow.setChecked(value)
        self.role_transition.setChecked(value)

    def set_all_ruletypes(self):
        self._set_ruletypes(True)

    def clear_all_ruletypes(self):
        self._set_ruletypes(False)

    #
    # Source criteria
    #

    def clear_source_error(self):
        self.clear_criteria_error(self.source, "Match the source role of the rule.")

    def set_source(self):
        try:
            self.query.source = self.source.text()
        except Exception as ex:
            self.log.error("Source role error: {0}".format(ex))
            self.set_criteria_error(self.source, ex)

    def set_source_regex(self, state):
        self.log.debug("Setting source_regex {0}".format(state))
        self.query.source_regex = state
        self.clear_source_error()
        self.set_source()

    #
    # Target criteria
    #

    def clear_target_error(self):
        self.clear_criteria_error(self.target, "Match the target role/type of the rule.")

    def set_target(self):
        try:
            self.query.target = self.target.text()
        except Exception as ex:
            self.log.error("Target type/role error: {0}".format(ex))
            self.set_criteria_error(self.target, ex)

    def set_target_regex(self, state):
        self.log.debug("Setting target_regex {0}".format(state))
        self.query.target_regex = state
        self.clear_target_error()
        self.set_target()

    #
    # Class criteria
    #

    def set_tclass(self):
        selected_classes = []
        for index in self.tclass.selectionModel().selectedIndexes():
            selected_classes.append(self.class_model.data(index, Qt.ItemDataRole.UserRole))

        self.query.tclass = selected_classes

    def invert_tclass_selection(self):
        invert_list_selection(self.tclass.selectionModel())

    #
    # Default criteria
    #

    def clear_default_error(self):
        self.clear_criteria_error(self.default_role, "Match the default role the rule.")

    def set_default_role(self):
        self.query.default_regex = self.default_regex.isChecked()

        try:
            self.query.default = self.default_role.text()
        except Exception as ex:
            self.log.error("Default role error: {0}".format(ex))
            self.set_criteria_error(self.default_role, ex)

    def set_default_regex(self, state):
        self.log.debug("Setting default_regex {0}".format(state))
        self.query.default_regex = state
        self.clear_default_error()
        self.set_default_role()

    #
    # Save/Load tab
    #
    def save(self):
        """Return a dictionary of settings."""
        if self.errors:
            raise TabFieldError("Field(s) are in error: {0}".
                                format(" ".join(o.objectName() for o in self.errors)))

        settings = {}
        save_checkboxes(self, settings, ["criteria_expander", "notes_expander",
                                         "allow", "role_transition",
                                         "source_indirect", "source_regex",
                                         "target_indirect", "target_regex",
                                         "default_regex"])
        save_lineedits(self, settings, ["source", "target", "default_role"])
        save_listviews(self, settings, ["tclass"])
        save_textedits(self, settings, ["notes"])
        return settings

    def load(self, settings):
        load_checkboxes(self, settings, ["criteria_expander", "notes_expander",
                                         "allow", "role_transition",
                                         "source_indirect", "source_regex",
                                         "target_indirect", "target_regex",
                                         "default_regex"])
        load_lineedits(self, settings, ["source", "target", "default_role"])
        load_listviews(self, settings, ["tclass"])
        load_textedits(self, settings, ["notes"])

    #
    # Results runner
    #

    def run(self, button):
        # right now there is only one button.
        rule_types = []

        for mode in [self.allow, self.role_transition]:
            if mode.isChecked():
                rule_types.append(mode.objectName())

        self.query.ruletype = rule_types
        self.query.source_indirect = self.source_indirect.isChecked()
        self.query.target_indirect = self.target_indirect.isChecked()

        # start processing
        self.busy.setLabelText("Processing query...")
        self.busy.show()
        self.raw_results.clear()
        self.thread.start()

    def update_complete(self, count):
        self.log.info("{0} RBAC rule(s) found.".format(count))

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
            self.raw_results.moveCursor(QTextCursor.MoveOperation.Start)

        self.busy.reset()
