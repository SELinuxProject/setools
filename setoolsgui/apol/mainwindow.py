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

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QAction, QApplication, QDialog, QFileDialog, QLineEdit, QMainWindow, \
                            QMenu, QMessageBox, QTreeWidgetItem, QVBoxLayout, QWidget
from setools import PermissionMap, SELinuxPolicy

from ..widget import SEToolsWidget
from ..logtosignal import LogHandlerToSignal
# Analysis tabs:
from .boolquery import BoolQueryTab
from .dta import DomainTransitionAnalysisTab
from .fsusequery import FSUseQueryTab
from .genfsconquery import GenfsconQueryTab
from .infoflow import InfoFlowAnalysisTab
from .mlsrulequery import MLSRuleQueryTab
from .rbacrulequery import RBACRuleQueryTab
from .rolequery import RoleQueryTab
from .terulequery import TERuleQueryTab
from .typeattrquery import TypeAttributeQueryTab
from .typequery import TypeQueryTab
from .userquery import UserQueryTab


class ApolMainWindow(SEToolsWidget, QMainWindow):

    def __init__(self, filename):
        super(ApolMainWindow, self).__init__()
        self.log = logging.getLogger(__name__)

        if filename:
            self._policy = SELinuxPolicy(filename)
        else:
            self._policy = None

        try:
            # try to load default permission map
            self._permmap = PermissionMap()
        except (IOError, OSError) as ex:
            self.log.info("Failed to load default permission map: {0}".format(ex))
            self._permmap = None

        self.setupUi()

    def setupUi(self):
        self.load_ui("apol.ui")

        self.tab_counter = 0

        self.update_window_title()

        # set up error message dialog
        self.error_msg = QMessageBox(self)
        self.error_msg.setStandardButtons(QMessageBox.Ok)

        # set up tab name editor
        self.tab_editor = QLineEdit(self.AnalysisTabs)
        self.tab_editor.setWindowFlags(Qt.Popup)

        # configure tab bar context menu
        tabBar = self.AnalysisTabs.tabBar()
        tabBar.addAction(self.rename_tab_action)
        tabBar.addAction(self.close_tab_action)
        tabBar.setContextMenuPolicy(Qt.ActionsContextMenu)

        # capture INFO and higher Python messages from setools lib for status bar
        handler = LogHandlerToSignal()
        handler.message.connect(self.statusbar.showMessage)
        logging.getLogger("setools").addHandler(handler)
        logging.getLogger("setoolsgui").addHandler(handler)

        # connect signals
        self.open_policy.triggered.connect(self.select_policy)
        self.open_permmap.triggered.connect(self.select_permmap)
        self.new_analysis.triggered.connect(self.choose_analysis)
        self.AnalysisTabs.tabCloseRequested.connect(self.close_tab)
        self.AnalysisTabs.tabBarDoubleClicked.connect(self.tab_name_editor)
        self.tab_editor.editingFinished.connect(self.rename_tab)
        self.rename_tab_action.triggered.connect(self.rename_active_tab)
        self.close_tab_action.triggered.connect(self.close_active_tab)
        self.copy_action.triggered.connect(self.copy)
        self.cut_action.triggered.connect(self.cut)
        self.paste_action.triggered.connect(self.paste)

        self.show()

    def update_window_title(self):
        if self._policy:
            self.setWindowTitle("{0} - apol".format(self._policy))
        else:
            self.setWindowTitle("apol")

    def select_policy(self):
        filename = QFileDialog.getOpenFileName(self, "Open policy file", ".")[0]
        if filename:
            try:
                self._policy = SELinuxPolicy(filename)
            except Exception as ex:
                self.error_msg.critical(self, "Policy loading error", str(ex))
            else:
                self.update_window_title()

                if self._permmap:
                    self._permmap.map_policy(self._policy)

    def select_permmap(self):
        filename = QFileDialog.getOpenFileName(self, "Open permission map file", ".")[0]
        if filename:
            try:
                self._permmap = PermissionMap(filename)
            except Exception as ex:
                self.error_msg.critical(self, "Permission map loading error", str(ex))
            else:

                if self._policy:
                    self._permmap.map_policy(self._policy)

    def choose_analysis(self):
        if not self._policy:
            self.error_msg.critical(self, "No open policy",
                                    "Cannot start a new analysis. Please open a policy first.")

            self.select_policy()

        if self._policy:
            # this check of self._policy is here in case someone
            # tries to start an analysis with no policy open, but then
            # cancels out of the policy file chooser or there is an
            # error opening the policy file.
            chooser = ChooseAnalysis(self, self._policy.mls)
            chooser.show()

    def create_new_analysis(self, tabtitle, tabclass):
        self.tab_counter += 1
        counted_name = "{0}: {1}".format(self.tab_counter, tabtitle)

        newtab = QWidget()
        newtab.setObjectName(counted_name)

        newanalysis = tabclass(newtab, self._policy, self._permmap)

        # create a vertical layout in the tab, place the analysis ui inside.
        tabLayout = QVBoxLayout()
        tabLayout.setContentsMargins(0, 0, 0, 0)
        tabLayout.addWidget(newanalysis)
        newtab.setLayout(tabLayout)

        index = self.AnalysisTabs.addTab(newtab, counted_name)
        self.AnalysisTabs.setTabToolTip(index, tabtitle)

    def tab_name_editor(self, index):
        if index >= 0:
            tab_area = self.AnalysisTabs.tabBar().tabRect(index)
            self.tab_editor.move(self.AnalysisTabs.mapToGlobal(tab_area.topLeft()))
            self.tab_editor.setText(self.AnalysisTabs.tabText(index))
            self.tab_editor.selectAll()
            self.tab_editor.show()
            self.tab_editor.setFocus()

    def close_active_tab(self):
        index = self.AnalysisTabs.currentIndex()
        if index >= 0:
            self.close_tab(index)

    def rename_active_tab(self):
        index = self.AnalysisTabs.currentIndex()
        if index >= 0:
            self.tab_name_editor(index)

    def close_tab(self, index):
        widget = self.AnalysisTabs.widget(index)
        widget.close()
        widget.deleteLater()
        self.AnalysisTabs.removeTab(index)

    def rename_tab(self):
        # this should never be negative since the editor is modal
        index = self.AnalysisTabs.currentIndex()

        self.tab_editor.hide()
        self.AnalysisTabs.setTabText(index, self.tab_editor.text())

    def copy(self):
        """Copy text from the currently-focused widget."""
        try:
            QApplication.instance().focusWidget().copy()
        except AttributeError:
            pass

    def cut(self):
        """Cut text from the currently-focused widget."""
        try:
            QApplication.instance().focusWidget().cut()
        except AttributeError:
            pass

    def paste(self):
        """Paste text into the currently-focused widget."""
        try:
            QApplication.instance().focusWidget().paste()
        except AttributeError:
            pass


class ChooseAnalysis(SEToolsWidget, QDialog):

    """
    Dialog for choosing a new analysis

    The below class attributes are used for populating
    the GUI contents and mapping them to the appropriate
    tab widget class for the analysis.

    The item_mapping attribute will be populated to
    map the tree list items to the analysis tab widgets.
    """

    _analysis_map = {"Domain Transition Analysis": DomainTransitionAnalysisTab,
                     "Information Flow Analysis": InfoFlowAnalysisTab}
    _components_map = {"Booleans": BoolQueryTab,
                       "Roles": RoleQueryTab,
                       "Types": TypeQueryTab,
                       "Type Attributes": TypeAttributeQueryTab,
                       "Users": UserQueryTab}
    _rule_map = {"RBAC Rules": RBACRuleQueryTab,
                 "TE Rules": TERuleQueryTab}
    _labeling_map = {"fs_use_* Statements": FSUseQueryTab,
                     "Genfscon Statements": GenfsconQueryTab}
    _analysis_choices = {"Components": _components_map,
                         "Rules": _rule_map,
                         "Analyses": _analysis_map,
                         "Labeling": _labeling_map}

    def __init__(self, parent, mls):
        super(ChooseAnalysis, self).__init__(parent)
        self.item_mapping = {}
        self.parent = parent
        self.setupUi(mls)

    def setupUi(self, mls):
        self.load_ui("choose_analysis.ui")
        self.buttonBox.accepted.connect(self.ok_clicked)
        self.analysisTypes.doubleClicked.connect(self.ok_clicked)

        if mls:
            self._rule_map["MLS Rules"] = MLSRuleQueryTab

        # populate the item list:
        self.analysisTypes.clear()
        for groupname, group in self._analysis_choices.items():
            groupitem = QTreeWidgetItem(self.analysisTypes)
            groupitem.setText(0, groupname)
            groupitem._tab_class = None
            for entryname, cls in group.items():
                item = QTreeWidgetItem(groupitem)
                item.setText(0, entryname)
                item._tab_class = cls
                groupitem.addChild(item)

        self.analysisTypes.expandAll()
        self.analysisTypes.sortByColumn(0, Qt.AscendingOrder)

    def ok_clicked(self):
        try:
            # .ui is set for single item selection.
            item = self.analysisTypes.selectedItems()[0]
            title = item.text(0)
            self.parent.create_new_analysis(title, item._tab_class)
        except (IndexError, TypeError):
            # IndexError: nothing is selected
            # TypeError: one of the group items was selected.
            pass
        else:
            self.accept()
