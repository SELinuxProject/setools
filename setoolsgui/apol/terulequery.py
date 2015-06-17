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

from PyQt5.QtCore import Qt, QSortFilterProxyModel, QStringListModel
from PyQt5.QtGui import QPalette, QTextCursor
from PyQt5.QtWidgets import QCompleter, QHeaderView, QScrollArea
from setools import TERuleQuery

from ..widget import SEToolsWidget
from .rulemodels import TERuleListModel
from .models import PermListModel, SEToolsListModel


class TERuleQueryTab(SEToolsWidget, QScrollArea):
    def __init__(self, parent, policy):
        super(TERuleQueryTab, self).__init__(parent)
        self.log = logging.getLogger(self.__class__.__name__)
        self.policy = policy
        self.query = TERuleQuery(policy)
        self.setupUi()

    def setupUi(self):
        self.load_ui("terulequery.ui")

        # set up source/target autocompletion
        typeattr_completion_list = [str(t) for t in self.policy.types()]
        typeattr_completion_list.extend(str(a) for a in self.policy.typeattributes())
        typeattr_completer_model = QStringListModel(self)
        typeattr_completer_model.setStringList(sorted(typeattr_completion_list))
        self.typeattr_completion = QCompleter()
        self.typeattr_completion.setModel(typeattr_completer_model)
        self.source.setCompleter(self.typeattr_completion)
        self.target.setCompleter(self.typeattr_completion)

        # set up default autocompletion
        type_completion_list = [str(t) for t in self.policy.types()]
        type_completer_model = QStringListModel(self)
        type_completer_model.setStringList(sorted(type_completion_list))
        self.type_completion = QCompleter()
        self.type_completion.setModel(type_completer_model)
        self.default_type.setCompleter(self.type_completion)

        # setup indications of errors on source/target/default
        self.orig_palette = self.source.palette()
        self.error_palette = self.source.palette()
        self.error_palette.setColor(QPalette.Base, Qt.red)
        self.clear_source_error()
        self.clear_target_error()
        self.clear_default_error()

        # populate class list
        self.class_model = SEToolsListModel(self)
        self.class_model.item_list = sorted(self.policy.classes())
        self.tclass.setModel(self.class_model)

        # populate perm list
        self.perms_model = PermListModel(self, self.policy)
        self.perms.setModel(self.perms_model)

        # populate bool list
        self.bool_model = SEToolsListModel(self)
        self.bool_model.item_list = sorted(self.policy.bools())
        self.bool_criteria.setModel(self.bool_model)

        # set up results
        self.table_results_model = TERuleListModel(self)
        self.sort_proxy = QSortFilterProxyModel(self)
        self.sort_proxy.setSourceModel(self.table_results_model)
        self.table_results.setModel(self.sort_proxy)

        # Ensure settings are consistent with the initial .ui state
        self.set_source_regex(self.source_regex.isChecked())
        self.set_target_regex(self.target_regex.isChecked())
        self.set_default_regex(self.default_regex.isChecked())
        self.criteria_frame.setHidden(not self.criteria_expander.isChecked())
        self.results_frame.setHidden(not self.results_expander.isChecked())
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
        self.perms.selectionModel().selectionChanged.connect(self.set_perms)
        self.default_type.textEdited.connect(self.clear_default_error)
        self.default_type.editingFinished.connect(self.set_default_type)
        self.default_regex.toggled.connect(self.set_default_regex)
        self.bool_criteria.selectionModel().selectionChanged.connect(self.set_bools)

    #
    # Ruletype criteria
    #

    def _set_ruletypes(self, value):
        self.allow.setChecked(value)
        self.auditallow.setChecked(value)
        self.neverallow.setChecked(value)
        self.dontaudit.setChecked(value)
        self.type_transition.setChecked(value)
        self.type_member.setChecked(value)
        self.type_change.setChecked(value)

    def set_all_ruletypes(self):
        self._set_ruletypes(True)

    def clear_all_ruletypes(self):
        self._set_ruletypes(False)

    #
    # Source criteria
    #

    def clear_source_error(self):
        self.source.setToolTip("Match the source type/attribute of the rule.")
        self.source.setPalette(self.orig_palette)

    def set_source(self):
        try:
            self.query.source = self.source.text()
        except Exception as ex:
            self.source.setToolTip("Error: " + str(ex))
            self.source.setPalette(self.error_palette)

    def set_source_regex(self, state):
        self.log.debug("Setting source_regex {0}".format(state))
        self.query.source_regex = state
        self.clear_source_error()
        self.set_source()

    #
    # Target criteria
    #

    def clear_target_error(self):
        self.target.setToolTip("Match the target type/attribute of the rule.")
        self.target.setPalette(self.orig_palette)

    def set_target(self):
        try:
            self.query.target = self.target.text()
        except Exception as ex:
            self.target.setToolTip("Error: " + str(ex))
            self.target.setPalette(self.error_palette)

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
            selected_classes.append(self.class_model.data(index, Qt.UserRole))

        self.query.tclass = selected_classes
        self.perms_model.set_classes(selected_classes)

    #
    # Permissions criteria
    #

    def set_perms(self):
        selected_perms = []
        for index in self.perms.selectionModel().selectedIndexes():
            selected_perms.append(self.perms_model.data(index, Qt.UserRole))

        self.query.perms = selected_perms

    #
    # Default criteria
    #

    def clear_default_error(self):
        self.default_type.setToolTip("Match the default type the rule.")
        self.default_type.setPalette(self.orig_palette)

    def set_default_type(self):
        self.query.default_regex = self.default_regex.isChecked()

        try:
            self.query.default = self.default_type.text()
        except Exception as ex:
            self.default_type.setToolTip("Error: " + str(ex))
            self.default_type.setPalette(self.error_palette)

    def set_default_regex(self, state):
        self.log.debug("Setting default_regex {0}".format(state))
        self.query.default_regex = state
        self.clear_default_error()
        self.set_default_type()

    #
    # Boolean criteria
    #

    def set_bools(self):
        selected_bools = []
        for index in self.bool_criteria.selectionModel().selectedIndexes():
            selected_bools.append(self.bool_model.data(index, Qt.UserRole))

        self.query.boolean = selected_bools

    #
    # Results runner
    #

    def run(self, button):
        # right now there is only one button.
        rule_types = []

        if self.allow.isChecked():
            rule_types.append("allow")
        if self.auditallow.isChecked():
            rule_types.append("auditallow")
        if self.neverallow.isChecked():
            rule_types.append("neverallow")
        if self.dontaudit.isChecked():
            rule_types.append("dontaudit")
        if self.type_transition.isChecked():
            rule_types.append("type_transition")
        if self.type_member.isChecked():
            rule_types.append("type_member")
        if self.type_change.isChecked():
            rule_types.append("type_change")

        self.query.ruletype = rule_types
        self.query.source_indirect = self.source_indirect.isChecked()
        self.query.target_indirect = self.target_indirect.isChecked()
        self.query.perms_equal = self.perms_equal.isChecked()
        self.query.boolean_equal = self.bools_equal.isChecked()

        # update results table
        results = list(self.query.results())
        self.table_results_model.set_rules(results)
        self.table_results.resizeColumnsToContents()

        # update raw results
        self.raw_results.clear()
        for line in results:
            self.raw_results.appendPlainText(str(line))

        self.raw_results.moveCursor(QTextCursor.Start)
