# Copyright 2015-2016, Tresys Technology, LLC
# SPDX-License-Identifier: LGPL-2.1-only

from collections import defaultdict
from contextlib import suppress
from functools import partial
import json
import logging
import os
import sys
from typing import cast, TYPE_CHECKING

import pkg_resources
from PyQt5 import QtCore, QtGui, QtWidgets
from setools import __version__, PermissionMap, SELinuxPolicy

from .config import ApolConfig
from .widgets import exception
from .widgets.permmap import PermissionMapEditor
from .widgets.summary import SummaryTab
from .widgets.tab import TAB_REGISTRY

# Supported analyses.  These are not directly used here, but
# will init the tab registry in widgets.tab for apol's analyses.
from .widgets import terulequery

if TYPE_CHECKING:
    from typing import Dict, Final, Optional
    from .widgets.tab import BaseAnalysisTabWidget

STYLESHEET: "Final" = "apol.css"

# Class of the tab that opens automatically when a policy is loaded.
INITIAL_TAB: "Final" = SummaryTab

# keys for workspace save file
SETTINGS_POLICY: "Final" = "__policy__"
SETTINGS_PERMMAP: "Final" = "__permmap__"
SETTINGS_TABS_LIST: "Final" = "__tabs__"
SETTINGS_TAB_TITLE: "Final" = "__title__"
SETTINGS_TAB_CLASS: "Final" = "__tab__"


class ApolWorkspace(QtWidgets.QTabWidget):

    policy: "Optional[SELinuxPolicy]"
    permmap: "Optional[PermissionMap]"

    policy_changed = QtCore.pyqtSignal(SELinuxPolicy)
    permmap_changed = QtCore.pyqtSignal(PermissionMap)

    def __init__(self, parent: "Optional[QtWidgets.QWidget]" = None) -> None:
        # __init__ here to type narrow the parent to the Apol main window
        super().__init__(parent)
        self.log = logging.getLogger(__name__)
        self.permmap = None
        self.policy = None
        self.config: "Final" = ApolConfig()

        self.setAutoFillBackground(True)
        self.setTabPosition(QtWidgets.QTabWidget.TabPosition.North)
        self.setTabsClosable(True)
        self.setMovable(True)
        self.setCurrentIndex(-1)

        # counter separate to the open tab count.  This increments for each new
        # tab so we can create a unique title for each tab, even if there are
        # many tabs with the same analysis.
        self.tab_counter = 0

        # set up tab name editor
        self.tab_editor = QtWidgets.QLineEdit(self)
        self.tab_editor.setWindowFlags(QtCore.Qt.WindowType.Popup)
        self.tab_editor.editingFinished.connect(self.rename_tab)

        #
        # Set up workspace actions. These will be pulled in by the
        # main window and added to the workspace menu.
        #

        self.open_policy_action = QtWidgets.QAction(self)
        self.open_policy_action.setIcon(
            QtGui.QIcon.fromTheme("dialog-open",
                                  self.style().standardIcon(
                                    QtWidgets.QStyle.StandardPixmap.SP_DialogOpenButton)))
        self.open_policy_action.setIconVisibleInMenu(True)
        self.open_policy_action.setText("&Open Policy")
        self.open_policy_action.setToolTip("Open an SELinux Policy")
        self.open_policy_action.setShortcut("Ctrl+O")
        self.open_policy_action.triggered.connect(self.select_policy)

        self.exit_apol_action = QtWidgets.QAction(self)
        self.exit_apol_action.setText("E&xit")
        self.exit_apol_action.setShortcut("Ctrl+Q")
        self.exit_apol_action.setIcon(
            QtGui.QIcon.fromTheme("dialog-close",
                                  self.style().standardIcon(
                                    QtWidgets.QStyle.StandardPixmap.SP_DialogCloseButton)))
        self.exit_apol_action.triggered.connect(self.parent().close)  # type: ignore

        self.new_analysis_action = QtWidgets.QAction(self)
        self.new_analysis_action.setIcon(
            QtGui.QIcon.fromTheme("file-icon",
                                  self.style().standardIcon(
                                    QtWidgets.QStyle.StandardPixmap.SP_FileIcon)))
        self.new_analysis_action.setIconVisibleInMenu(True)
        self.new_analysis_action.setText("New Analysis")
        self.new_analysis_action.setToolTip("Start a new analysis on this policy.")
        self.new_analysis_action.setShortcut("Ctrl+N")
        self.new_analysis_action.triggered.connect(self.choose_analysis)

        self.new_from_settings_action = QtWidgets.QAction(self)
        self.new_from_settings_action.setText("New Analysis From Settings")
        self.new_from_settings_action.setToolTip("Start a new analysis using settings from a file.")
        self.new_from_settings_action.setShortcut("Ctrl+Shift+N")
        self.new_from_settings_action.triggered.connect(self.new_analysis_from_config)

        self.save_settings_action = QtWidgets.QAction(self)
        self.save_settings_action.setText("Save Tab Settings")
        self.save_settings_action.setToolTip("Save the current tab\'s settings to file.")
        self.save_settings_action.setShortcut("Ctrl+S")
        self.save_settings_action.triggered.connect(self.save_settings)

        self.load_settings_action = QtWidgets.QAction(self)
        self.load_settings_action.setText("Load Tab Settings")
        self.load_settings_action.setToolTip("Load settings for the current tab.")
        self.load_settings_action.setShortcut("Ctrl+L")
        self.load_settings_action.triggered.connect(self.load_settings)

        self.dupe_tab_action = QtWidgets.QAction(self)
        self.dupe_tab_action.setText("&Duplicate Tab")
        self.dupe_tab_action.setToolTip("Duplicate the active tab.")
        self.dupe_tab_action.setShortcut("Ctrl+Shift+K")
        self.dupe_tab_action.triggered.connect(self.dupe_tab)

        self.close_tab_action = QtWidgets.QAction(self)
        self.close_tab_action.setText("&Close Tab")
        self.close_tab_action.setToolTip("Close the active tab.")
        self.close_tab_action.setShortcut("Ctrl+W")
        self.close_tab_action.triggered.connect(self.close_tab)

        self.load_workspace_action = QtWidgets.QAction(self)
        self.load_workspace_action.setText("Load Workspace")
        self.load_workspace_action.setToolTip("Load workspace from file.")
        self.load_workspace_action.setShortcut("Ctrl+Shift+L")
        self.load_workspace_action.triggered.connect(self.load_workspace)

        self.save_workspace_action = QtWidgets.QAction(self)
        self.save_workspace_action.setText("Save Workspace")
        self.save_workspace_action.setToolTip("Save workspace to file.")
        self.save_workspace_action.setShortcut("Ctrl+Shift+S")
        self.save_workspace_action.triggered.connect(self.save_workspace)

        self.help_action = QtWidgets.QWhatsThis.createAction(self)

        self.about_apol_action = QtWidgets.QAction(self)
        self.about_apol_action.setText("About Apol")
        self.about_apol_action.triggered.connect(self.about_apol)

        self.cut_action = QtWidgets.QAction(self)
        self.cut_action.setText("Cut")
        self.cut_action.setShortcut("Ctrl+X")
        self.cut_action.triggered.connect(self.cut)

        self.copy_action = QtWidgets.QAction(self)
        self.copy_action.setText("Copy")
        self.copy_action.setShortcut("Ctrl+C")
        self.copy_action.triggered.connect(self.copy)

        self.paste_action = QtWidgets.QAction(self)
        self.paste_action.setText("Paste")
        self.paste_action.setShortcut("Ctrl+V")
        self.paste_action.triggered.connect(self.paste)

        self.open_permmap = QtWidgets.QAction(self)
        self.open_permmap.setText("Open Permission Map")
        self.open_permmap.setToolTip("Open permission map used for information flow analysis")
        self.open_permmap.triggered.connect(self.select_permmap)

        # these two tab actions are to have a global shortcut and
        # entries in the workspace menu.

        self.close_policy_action = QtWidgets.QAction(self)
        self.close_policy_action.setText("Close Policy")
        self.close_policy_action.setToolTip("Close the current policy. Closes all analyses too.")
        self.close_policy_action.triggered.connect(self.close_policy)

        self.edit_permmap_action = QtWidgets.QAction(self)
        self.edit_permmap_action.setText("Edit Permission Map")
        self.edit_permmap_action.triggered.connect(self.edit_permmap)

        self.save_permmap_action = QtWidgets.QAction(self)
        self.save_permmap_action.setText("Save Permission Map")
        self.save_permmap_action.triggered.connect(self.save_permmap)

        # File menu
        self.menu_File = QtWidgets.QMenu(self)
        self.menu_File.setTitle("&File")
        self.menu_File.addAction(self.open_policy_action)
        self.menu_File.addAction(self.close_policy_action)
        self.menu_File.addSeparator()
        self.menu_File.addAction(self.exit_apol_action)

        # Workspace menu
        self.menuWorkspace = QtWidgets.QMenu(self)
        self.menuWorkspace.setTitle("Workspace")
        self.menuWorkspace.addAction(self.new_analysis_action)
        self.menuWorkspace.addAction(self.new_from_settings_action)
        self.menuWorkspace.addSeparator()
        self.menuWorkspace.addAction(self.load_settings_action)
        self.menuWorkspace.addAction(self.save_settings_action)
        self.menuWorkspace.addAction(self.dupe_tab_action)
        self.menuWorkspace.addAction(self.close_tab_action)
        self.menuWorkspace.addSeparator()
        self.menuWorkspace.addAction(self.load_workspace_action)
        self.menuWorkspace.addAction(self.save_workspace_action)

        # Edit menu
        self.menu_Edit = QtWidgets.QMenu(self)
        self.menu_Edit.setTitle("&Edit")
        self.menu_Edit.addAction(self.cut_action)
        self.menu_Edit.addAction(self.copy_action)
        self.menu_Edit.addAction(self.paste_action)

        # Permission Map menu
        self.menuPerm_Map = QtWidgets.QMenu(self)
        self.menuPerm_Map.setTitle("Permission &Map")
        self.menuPerm_Map.addAction(self.open_permmap)
        self.menuPerm_Map.addAction(self.edit_permmap_action)
        self.menuPerm_Map.addAction(self.save_permmap_action)

        # Help menu
        self.menu_Help = QtWidgets.QMenu(self)
        self.menu_Help.setTitle("&Help")
        self.menu_Help.addAction(self.help_action)
        self.menu_Help.addSeparator()
        self.menu_Help.addAction(self.about_apol_action)

        self.addAction(self.menu_File.menuAction())
        self.addAction(self.menuWorkspace.menuAction())
        self.addAction(self.menu_Edit.menuAction())
        self.addAction(self.menuPerm_Map.menuAction())
        self.addAction(self.menu_Help.menuAction())

        #
        # Add tab context menu
        #
        tab_bar = self.tabBar()
        tab_bar.setContextMenuPolicy(QtCore.Qt.ContextMenuPolicy.CustomContextMenu)
        tab_bar.customContextMenuRequested.connect(self.tab_bar_context_menu)

        #
        # Connect signals
        #
        self.policy_changed.connect(self.update_window_title)
        self.policy_changed.connect(self.handle_policy_change)
        self.tabCloseRequested.connect(self.close_tab)
        self.tabBarDoubleClicked.connect(self.tab_name_editor)

        QtCore.QMetaObject.connectSlotsByName(self)

    #
    # Reimplemented methods for typing purposes
    #
    def widget(self, index: int) -> "BaseAnalysisTabWidget":
        return cast("BaseAnalysisTabWidget", super().widget(index))

    #
    # Main window handling
    #
    def update_window_title(self) -> None:
        with suppress(Exception):
            if self.policy:
                self.parentWidget().setWindowTitle(f"{self.policy} - apol")
            else:
                self.parentWidget().setWindowTitle("apol")

    #
    # Policy handling
    #
    def select_policy(self):
        if self.policy and self.count() > 0:
            reply = QtWidgets.QMessageBox.question(
                self,
                "Continue?",
                "Loading a policy will close all existing analyses.  Continue?",
                QtWidgets.QMessageBox.StandardButtons() |
                QtWidgets.QMessageBox.StandardButton.Yes |
                QtWidgets.QMessageBox.StandardButton.No)

            if reply == QtWidgets.QMessageBox.StandardButton.No:
                return

        filename = QtWidgets.QFileDialog.getOpenFileName(
            self,
            "Open policy file",
            ".",
            "SELinux Policies (policy.* sepolicy);;"
            "All Files (*)")[0]

        if filename:
            self.load_policy(filename)

    def load_policy(self, filename) -> None:
        try:
            self.policy = SELinuxPolicy(filename)
            self.policy_changed.emit(self.policy)

            if self.permmap:
                with suppress(Exception):
                    self.permmap.map_policy(self.policy)
                    self.permmap_changed.emit(self.permmap)

        except Exception as ex:
            self.log.critical("Failed to load policy \"{0}\"".format(filename))
            QtWidgets.QMessageBox().critical(self, "Policy loading error", str(ex))

    def close_policy(self):
        if self.count() > 0:
            reply = QtWidgets.QMessageBox.question(
                self, "Continue?",
                "Closing a policy will close all existing analyses.  Continue?",
                QtWidgets.QMessageBox.StandardButtons() |
                QtWidgets.QMessageBox.StandardButton.Yes |
                QtWidgets.QMessageBox.StandardButton.No)

            if reply == QtWidgets.QMessageBox.StandardButton.No:
                return

        self.policy = None
        self.clear()

    #
    # Permission map handling
    #
    def select_permmap(self):
        filename = QtWidgets.QFileDialog.getOpenFileName(self, "Open permission map file", ".")[0]
        if filename:
            self.load_permmap(filename)

    def load_permmap(self, filename=None):
        try:
            self.permmap = PermissionMap(filename)

            if self.policy:
                with suppress(Exception):
                    self.permmap.map_policy(self.policy)

            self.permmap_changed.emit(self.permmap)

        except Exception as ex:
            self.log.critical("Failed to load default permission map: {0}".format(ex))
            QtWidgets.QMessageBox().critical(
                self,
                "Permission map loading error",
                str(ex))

    def edit_permmap(self):
        if not self.permmap:
            QtWidgets.QMessageBox().critical(
                self,
                "No open permission map",
                "Cannot edit permission map. Please open a map first.")

            self.select_permmap()

        # in case user cancels out of choosing a permmap, recheck
        if self.permmap:
            editor = PermissionMapEditor(self.permmap, edit=True, parent=self)
            editor.apply_permmap.connect(self.permmap_changed)
            editor.setAttribute(QtCore.Qt.WidgetAttribute.WA_DeleteOnClose)
            editor.show()

    def save_permmap(self):
        path = str(self.permmap) if self.permmap else "perm_map"
        filename = QtWidgets.QFileDialog.getSaveFileName(self, "Save permission map file", path)[0]
        if filename:
            try:
                self.permmap.save(filename)
            except Exception as ex:
                self.log.critical("Failed to save permission map: {0}".format(ex))
                QtWidgets.QMessageBox().critical(self, "Permission map saving error", str(ex))

    #
    # Tab handling
    #
    def choose_analysis(self):
        if not self.policy:
            QtWidgets.QMessageBox().critical(
                self,
                "No open policy",
                "Cannot start a new analysis. Please open a policy first.")

            self.select_policy()

        if self.policy:
            # this check of self._policy is here in case someone
            # tries to start an analysis with no policy open, but then
            # cancels out of the policy file chooser or there is an
            # error opening the policy file.
            ChooseAnalysis(self.policy.mls, parent=self)

    def create_new_analysis(self, tab_class: "BaseAnalysisTabWidget") -> int:
        self.tab_counter += 1
        counted_name = "{0}: {1}".format(self.tab_counter, tab_class.tab_title)

        assert self.policy
        assert self.permmap

        new_tab = tab_class(self.policy, self.permmap,
                            parent=self)
        new_tab.setObjectName(counted_name)
        self.permmap_changed.connect(new_tab.handle_permmap_change)
        index = self.addTab(new_tab, counted_name)
        self.setTabToolTip(index, tab_class.tab_title)
        self.setCurrentIndex(index)
        self.toggle_workspace_actions()

        return index

    def tab_bar_context_menu(self, pos: QtCore.QPoint) -> None:
        """Display a context menu for the tab bar."""
        tab_bar = self.tabBar()
        index = tab_bar.tabAt(pos)

        #
        # Generate context menu for this specific tab index, which may not
        # be the active tab.
        #
        rename_tab_action = QtWidgets.QAction(self)
        rename_tab_action.setText("&Rename Tab")
        rename_tab_action.setToolTip("Rename this tab.")
        rename_tab_action.triggered.connect(partial(self.tab_name_editor, index))

        dupe_tab_action = QtWidgets.QAction(self)
        dupe_tab_action.setText("&Duplicate Tab")
        dupe_tab_action.setToolTip("Duplicate this tab.")
        dupe_tab_action.triggered.connect(partial(self.dupe_tab, index))

        close_tab_action = QtWidgets.QAction(self)
        close_tab_action.setText("&Close Tab")
        close_tab_action.setToolTip("Close this tab.")
        close_tab_action.triggered.connect(partial(self.close_tab, index))

        menu = QtWidgets.QMenu(self)
        menu.addAction(rename_tab_action)
        menu.addAction(dupe_tab_action)
        menu.addAction(close_tab_action)
        menu.setAttribute(QtCore.Qt.WidgetAttribute.WA_DeleteOnClose)
        menu.popup(tab_bar.mapToGlobal(pos))

    def tab_name_editor(self, index: "Optional[int]" = None) -> None:
        if index is None:
            index = self.currentIndex()

        if index < 0:
            return

        tab_area = self.tabBar().tabRect(index)
        self.tab_editor.move(self.mapToGlobal(tab_area.topLeft()))
        self.tab_editor.setText(self.tabText(index))
        self.tab_editor.selectAll()
        self.tab_editor.show()
        self.tab_editor.setFocus()

    def dupe_tab(self, index: "Optional[int]" = None) -> None:
        """Duplicate the active tab"""
        if index is None:
            index = self.currentIndex()

        if index < 0:
            return

        settings = self._get_settings(index)
        new_index = self.create_new_analysis(type(self.widget(index)))
        self._put_settings(settings, new_index)

    def close_tab(self, index: "Optional[int]" = None) -> None:
        """Close a tab specified by index."""
        if index is None:
            index = self.currentIndex()

        if index < 0:
            return

        widget = self.widget(index)
        widget.close()
        self.removeTab(index)
        self.toggle_workspace_actions()

    def rename_tab(self) -> None:
        # this should never be negative since the editor is modal
        index = self.currentIndex()
        tab = self.widget(index)
        title = self.tab_editor.text()

        self.tab_editor.hide()

        self.setTabText(index, title)
        tab.setObjectName(title)

    #
    # Workspace actions
    #
    def clear(self) -> None:
        """Close all tabs."""
        super().clear()
        self.toggle_workspace_actions()

    def handle_policy_change(self, policy: SELinuxPolicy) -> None:
        self.log.debug(f"Received policy change signal to {policy}.")
        self.clear()

        # Open up a new instance of the initial tab if no tabs exist.
        self.log.debug(f"Opening new {INITIAL_TAB} tab.")
        self.create_new_analysis(INITIAL_TAB)

    def toggle_workspace_actions(self) -> None:
        """
        Enable or disable workspace actions depending on
        how many tabs are open and if a policy is open.

        This is a slot for the QTabWidget.currentChanged()
        signal, though index is ignored.
        """
        open_tabs = self.count() > 0
        open_policy = self.policy is not None

        self.log.debug("{0} actions requiring an open policy.".
                       format("Enabling" if open_policy else "Disabling"))
        self.log.debug("{0} actions requiring open tabs.".
                       format("Enabling" if open_tabs else "Disabling"))

        self.save_settings_action.setEnabled(open_tabs)
        self.save_workspace_action.setEnabled(open_tabs)
        self.new_analysis_action.setEnabled(open_policy)
        self.new_from_settings_action.setEnabled(open_policy)
        self.load_settings_action.setEnabled(open_tabs)
        self.close_policy_action.setEnabled(open_policy)

    def _get_settings(self, index: "Optional[int]" = None) -> "Dict":
        """Return a dictionary with the settings of the tab at the specified index."""
        if index is None:
            index = self.currentIndex()

        assert index >= 0, "Tab index is negative in _get_settings.  This is an SETools bug."
        tab = self.widget(index)

        settings = tab.save()

        # add the tab info to the settings.
        settings[SETTINGS_TAB_TITLE] = self.tabText(index)
        settings[SETTINGS_TAB_CLASS] = type(tab).__name__

        return settings

    def _put_settings(self, settings, index=None):
        """Load the settings into the specified tab."""

        if index is None:
            index = self.currentIndex()

        assert index >= 0, "Tab index is negative in _put_settings.  This is an SETools bug."
        tab = self.widget(index)

        if settings[SETTINGS_TAB_CLASS] != type(tab).__name__:
            raise TypeError("The current tab ({0}) does not match the tab in the settings file "
                            "({1}).".format(type(tab).__name__, settings[SETTINGS_TAB_CLASS]))

        try:
            self.setTabText(index, str(settings[SETTINGS_TAB_TITLE]))
        except KeyError:
            self.log.warning("Settings file does not have a title setting.")

        tab.load(settings)

    def load_settings(self, new=False):
        filename = QtWidgets.QFileDialog.getOpenFileName(
            self,
            "Open settings file",
            ".",
            "Apol Tab Settings File (*.apolt);;"
            "All Files (*)")[0]
        if not filename:
            return

        try:
            with open(filename, "r") as fd:
                settings = json.load(fd)
        except ValueError as ex:
            self.log.critical("Invalid settings file \"{filename}\"")
            QtWidgets.QMessageBox().critical(
                self,
                "Failed to load settings",
                "Invalid settings file: \"{filename}\"")
            return
        except OSError as ex:
            self.log.critical(f"Unable to load settings file \"{ex.filename}\": {ex.strerror}")
            QtWidgets.QMessageBox().critical(
                self,
                "Failed to load settings",
                f"Failed to load \"{ex.filename}\": {ex.strerror}")
            return
        except Exception as ex:
            self.log.critical("Unable to load settings file \"{filename}\": {ex}")
            QtWidgets.QMessageBox().critical(
                self,
                "Failed to load settings",
                str(ex))
            return

        self.log.info(f"Loading analysis settings from \"{filename}\"")

        if new:
            try:
                tabclass = TAB_REGISTRY[settings[SETTINGS_TAB_CLASS]]
            except KeyError:
                self.log.critical(f"Missing analysis type in \"{filename}\"")
                QtWidgets.QMessageBox().critical(
                    self,
                    "Failed to load settings",
                    "The type of analysis is missing in the settings file.")
                return

            # The tab title will be set by _put_settings.
            index = self.create_new_analysis(tabclass)
        else:
            index = None

        try:
            self._put_settings(settings, index)
        except Exception as ex:
            self.log.critical("Error loading settings file \"{0}\": {1}".format(filename, ex))
            QtWidgets.QMessageBox().critical(
                self,
                "Failed to load settings",
                f"Error loading settings file \"{filename}\":\n\n{ex}")
        else:
            self.log.info("Successfully loaded analysis settings from \"{0}\"".format(filename))

    def new_analysis_from_config(self):
        self.load_settings(new=True)

    def save_settings(self):
        try:
            settings = self._get_settings()

        except exception.TabFieldError as ex:
            self.log.critical(f"Errors in the query prevent saving the settings. {ex}")
            QtWidgets.QMessageBox().critical(
                self,
                "Unable to save settings",
                "Please resolve errors in the tab before saving the settings.")
            return

        filename = QtWidgets.QFileDialog.getSaveFileName(
            self,
            "Save analysis tab settings",
            "analysis.apolt",
            "Apol Tab Settings File (*.apolt);;"
            "All Files (*)")[0]

        if not filename:
            return

        try:
            with open(filename, "w") as fd:
                json.dump(settings, fd, indent=1)
        except OSError as ex:
            self.log.critical(f"Unable to save settings file \"{ex.filename}\": {ex.strerror}")
            QtWidgets.QMessageBox().critical(
                self,
                "Failed to save settings",
                f"Failed to save \"{ex.filename}\": {ex.strerror}")
        except Exception as ex:
            self.log.critical(f"Unable to save settings file \"{filename}\": {ex}")
            QtWidgets.QMessageBox().critical(
                self,
                "Failed to save settings",
                str(ex))
        else:
            self.log.info(f"Successfully saved settings file \"{filename}\"")

    def load_workspace(self):
        # 1. if number of tabs > 0, check if we really want to do this
        if self.count() > 0:
            reply = QtWidgets.QMessageBox.question(
                self, "Continue?",
                "Loading a workspace will close all existing analyses.  Continue?",
                QtWidgets.QMessageBox.StandardButtons(QtWidgets.QMessageBox.StandardButton.Yes) |
                QtWidgets.QMessageBox.StandardButton.No)

            if reply == QtWidgets.QMessageBox.StandardButton.No:
                return

        # 2. try to load the workspace file, if we fail, bail
        filename = QtWidgets.QFileDialog.getOpenFileName(
            self,
            "Open workspace file",
            ".",
            "Apol Workspace Files (*.apolw);;"
            "All Files (*)")[0]

        if not filename:
            return

        try:
            with open(filename, "r") as fd:
                workspace = json.load(fd)
        except ValueError as ex:
            self.log.critical(f"Invalid workspace file \"{filename}\"")
            QtWidgets.QMessageBox().critical(
                self,
                "Failed to load workspace",
                f"Invalid workspace file: \"{filename}\"")
            return
        except OSError as ex:
            self.log.critical(f"Unable to load workspace file \"{ex.filename}\": {ex.strerror}")
            QtWidgets.QMessageBox().critical(
                self,
                "Failed to load workspace",
                f"Failed to load \"{ex.filename}\": {ex.strerror}")
            return
        except Exception as ex:
            self.log.critical(f"Unable to load workspace file \"{filename}\": {ex}")
            QtWidgets.QMessageBox().critical(self, "Failed to load workspace", str(ex))
            return

        # 3. close all tabs.  Explicitly do this to avoid the question
        #    about closing the policy with tabs open.
        self.clear()

        # 4. close policy
        self.close_policy()

        # 5. try to open the specified policy, if we fail, bail.  Note:
        #    handling exceptions from the policy load is done inside
        #    the load_policy function, so only the KeyError needs to be caught here
        try:
            self.load_policy(workspace[SETTINGS_POLICY])
        except KeyError:
            self.log.critical(f"Missing policy in workspace file \"{filename}\"")
            QtWidgets.QMessageBox().critical(
                self,
                "Aborting workspace load.",
                f"Missing policy in workspace file \"{filename}\"")

        if self.policy is None:
            self.log.critical(f"The policy could not be loaded in workspace file \"{filename}\"")
            QtWidgets.QMessageBox().critical(
                self,
                "Aborting workspace load.",
                f"The policy could not be loaded in workspace file \"{filename}\".")
            return

        # 6. try to open the specified perm map, if we fail,
        #    tell the user we will continue with the default map; load the default map
        #    Note: handling exceptions from the map load is done inside
        #    the load_permmap function, so only the KeyError needs to be caught here
        try:
            self.load_permmap(workspace[SETTINGS_PERMMAP])
        except KeyError:
            self.log.warning(f"Missing permission map in workspace file \"{filename}\"")
            QtWidgets.QMessageBox().warning(
                self,
                "Missing permission map setting.",
                f"Missing permission map in workspace file \"{filename}\". "
                "Loading default permission map.")

        if self.permmap is None:
            self.load_permmap()

        # 7. try to open all tabs and apply settings.  Record any errors
        try:
            tab_list = list(workspace[SETTINGS_TABS_LIST])
        except KeyError:
            self.log.critical(f"Missing tab list in workspace file \"{filename}\"")
            QtWidgets.QMessageBox().critical(
                self,
                "Failed to load workspace",
                "The workspace file is missing the tab list.  Aborting.")
            return
        except TypeError:
            self.log.critical("Invalid tab list in workspace file.")
            QtWidgets.QMessageBox().critical(
                self,
                "Failed to load workspace",
                "The tab count is invalid.  Aborting.")
            return

        loading_errors = []
        for i, settings in enumerate(tab_list):
            try:
                tabclass = TAB_REGISTRY[settings[SETTINGS_TAB_CLASS]]
            except KeyError:
                error_str = f"Missing analysis type for tab {i}. Skipping this tab."
                self.log.error(error_str)
                loading_errors.append(error_str)
                continue

            # The tab title will be set by _put_settings.
            index = self.create_new_analysis(tabclass)

            try:
                self._put_settings(settings, index)
            except Exception as ex:
                error_str = "Error loading settings for tab {0}: {1}".format(i, ex)
                self.log.error(error_str)
                loading_errors.append(error_str)

        self.log.info("Completed loading workspace from \"{0}\"".format(filename))

        # 8. if there are any errors, open a dialog with the
        #    complete list of tab errors
        if loading_errors:
            QtWidgets.QMessageBox().warning(
                self,
                "Errors while loading workspace:",
                "There were errors while loading the workspace:\n\n{0}".
                format("\n\n".join(loading_errors)))

    def save_workspace(self):
        workspace = {}
        save_errors = []

        workspace[SETTINGS_POLICY] = os.path.abspath(str(self.policy))
        workspace[SETTINGS_PERMMAP] = os.path.abspath(str(self.permmap))
        workspace[SETTINGS_TABS_LIST] = []

        for index in range(self.count()):
            tab = self.widget(index)

            try:
                settings = tab.save()
            except exception.TabFieldError as ex:
                tab_name = self.tabText(index)
                save_errors.append(tab_name)
                self.log.error("Error: tab \"{0}\": {1}".format(tab_name, str(ex)))
            else:
                # add the tab info to the settings.
                settings[SETTINGS_TAB_TITLE] = self.tabText(index)
                settings[SETTINGS_TAB_CLASS] = type(tab).__name__

                workspace[SETTINGS_TABS_LIST].append(settings)

        if save_errors:
            self.log.critical("Errors in tabs prevent saving the workspace.")
            QtWidgets.QMessageBox().critical(
                self,
                "Unable to save workspace",
                f"Please resolve errors in the following tabs before saving the "
                "workspace:\n\n{0}".format('\n'.join(save_errors)))
            return

        filename = QtWidgets.QFileDialog.getSaveFileName(
            self,
            "Save analysis workspace",
            "workspace.apolw",
            "Apol Workspace Files (*.apolw);;"
            "All Files (*)")[0]

        if not filename:
            return

        with open(filename, "w") as fd:
            json.dump(workspace, fd, indent=1)

    #
    # Edit actions
    #
    def copy(self):
        """Copy text from the currently-focused widget."""
        with suppress(Exception):
            QtWidgets.QApplication.instance().focusWidget().copy()

    def cut(self):
        """Cut text from the currently-focused widget."""
        with suppress(Exception):
            QtWidgets.QApplication.instance().focusWidget().cut()

    def paste(self):
        """Paste text into the currently-focused widget."""
        with suppress(Exception):
            QtWidgets.QApplication.instance().focusWidget().paste()

    #
    # Help actions
    #
    def about_apol(self):
        QtWidgets.QMessageBox.about(
            self,
            "About Apol",
            f"""
            <h1><b>Apol {__version__}</b></h1>

            <p>Apol is a graphical SELinux policy analysis tool and part of
            <a href="https://github.com/SELinuxProject/setools/wiki"> SETools</a>.</p>

            <p>Copyright (C) 2015-2016, Tresys Technology</p>

            <p>Copyright (C) 2016-2023, Chris PeBenito <pebenito@ieee.org></p>
            """)


class ChooseAnalysis(QtWidgets.QDialog):

    """
    Dialog for choosing a new analysis

    The below class attributes are used for populating
    the GUI contents and mapping them to the appropriate
    tab widget class for the analysis.
    """

    def __init__(self, mls: bool, parent: "ApolWorkspace"):
        super().__init__(parent)

        # populate the analysis choices tree:
        self.analysis_choices: "Dict[str, Dict[str, BaseAnalysisTabWidget]]" = defaultdict(dict)
        for clsobj in TAB_REGISTRY.values():
            self.analysis_choices[clsobj.section.name][clsobj.tab_title] = clsobj

        self.setupUi(mls)

    def setupUi(self, mls: bool) -> None:
        self.setWindowTitle("New Analysis")
        self.setAttribute(QtCore.Qt.WidgetAttribute.WA_DeleteOnClose)

        verticalLayout = QtWidgets.QVBoxLayout(self)

        label = QtWidgets.QLabel(self)
        label.setText("Choose a new analysis to start:")
        verticalLayout.addWidget(label)

        # Create tree widget for analysis selection
        self.analysisTypes = QtWidgets.QTreeWidget(self)
        self.analysisTypes.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.analysisTypes.setHeaderHidden(True)
        self.analysisTypes.setExpandsOnDoubleClick(True)
        self.analysisTypes.setColumnCount(1)
        self.analysisTypes.header().setVisible(False)
        self.analysisTypes.headerItem().setText(0, "Analyses")
        self.analysisTypes.itemDoubleClicked['QTreeWidgetItem*', 'int'].connect(self.accept)
        verticalLayout.addWidget(self.analysisTypes)

        # Populate analyses widget
        self.analysisTypes.clear()
        for groupname, group in self.analysis_choices.items():
            groupitem = QtWidgets.QTreeWidgetItem(self.analysisTypes)
            groupitem.setText(0, groupname)
            for entryname, cls in group.items():
                if cls.mlsonly and not mls:
                    continue

                item = QtWidgets.QTreeWidgetItem(groupitem)
                item.setText(0, entryname)
                item.setData(0, QtCore.Qt.ItemDataRole.UserRole, cls)
                groupitem.addChild(item)

        self.analysisTypes.expandAll()
        self.analysisTypes.sortByColumn(0, QtCore.Qt.SortOrder.AscendingOrder)

        buttonBox = QtWidgets.QDialogButtonBox(self)
        buttonBox.setOrientation(QtCore.Qt.Orientation.Horizontal)
        buttonBox.setStandardButtons(
            QtWidgets.QDialogButtonBox.Cancel |
            QtWidgets.QDialogButtonBox.Ok)
        verticalLayout.addWidget(buttonBox)

        buttonBox.rejected.connect(self.reject)
        buttonBox.accepted.connect(self.accept)

        QtCore.QMetaObject.connectSlotsByName(self)

        self.show()

    def accept(self, item: "Optional[QtWidgets.QTreeWidgetItem]" = None) -> None:
        parent = self.parent()
        assert isinstance(parent, ApolWorkspace)  # type narrowing for mypy
        try:
            if not item:
                # tree widget is set for single item selection.
                item = self.analysisTypes.selectedItems()[0]

            tab_class = cast("BaseAnalysisTabWidget",
                             item.data(0, QtCore.Qt.ItemDataRole.UserRole))
            parent.create_new_analysis(tab_class)
        except (IndexError, AttributeError):
            # IndexError: nothing is selected
            # AttributeError: one of the group items was selected.
            return
        else:
            super().accept()


def run_apol(policy: "Optional[str]" = None) -> int:
    """Library entrypoint for apol"""
    app = QtWidgets.QApplication(sys.argv)

    # load apol stylesheet
    distro = pkg_resources.get_distribution("setools")
    with open(f"{distro.location}/setoolsgui/{STYLESHEET}") as fd:
        app.setStyleSheet(fd.read())

    #
    # Create main window
    #
    mw = QtWidgets.QMainWindow()
    mw.setStatusBar(QtWidgets.QStatusBar(mw))
    mw.setMenuBar(QtWidgets.QMenuBar(mw))

    #
    # Create central widget
    #
    AnalysisTabs = ApolWorkspace(mw)
    mw.setCentralWidget(AnalysisTabs)
    # Add actions from the central widget to the menu bar.
    mw.menuBar().addActions(AnalysisTabs.actions())

    #
    # Configure top-level toolbar
    #
    toolbar = QtWidgets.QToolBar(mw)
    toolbar.setFloatable(True)
    toolbar.setMovable(True)
    toolbar.addAction(AnalysisTabs.open_policy_action)
    toolbar.addAction(AnalysisTabs.new_analysis_action)
    toolbar.addSeparator()
    toolbar.addAction(AnalysisTabs.help_action)
    mw.addToolBar(QtCore.Qt.ToolBarArea.TopToolBarArea, toolbar)

    #
    # Final loading.
    #
    AnalysisTabs.load_permmap()

    if policy:
        AnalysisTabs.load_policy(policy)

    mw.show()

    return app.exec_()