# SPDX-License-Identifier: LGPL-2.1-only

from contextlib import suppress
from enum import Enum
import logging
from typing import TYPE_CHECKING, cast

from PyQt5 import QtCore, QtGui, QtWidgets

from .exception import TabFieldError
from .models.typing import QObjectType
from .queryupdater import QueryResultsUpdater
from .tableview import SEToolsTableView
from ..logtosignal import LogHandlerToSignal

if TYPE_CHECKING:
    from typing import Dict, Final, List, Optional, Tuple, Type, Union
    from setools import PermissionMap
    from setools.query import PolicyQuery
    from .criteria.criteria import CriteriaWidget
    from .models.table import SEToolsTableModel

# workspace settings keys
SETTINGS_NOTES = "notes"
SETTINGS_SHOW_NOTES = "show_notes"
SETTINGS_SHOW_CRITERIA = "show_criteria"

# Show criteria default setting (checked)
CRITERIA_DEFAULT_CHECKED = True
# Show notes default setting (unchecked)
NOTES_DEFAULT_CHECKED = False


class AnalysisSection(Enum):

    """Groupings of analysis tabs"""

    Analysis = 1
    Components = 2
    General = 3
    Labeling = 4
    Other = 5
    Rules = 6


TAB_REQUIRED_CLASSVARS = ("section", "tab_title", "mlsonly")
TAB_REGISTRY: "Dict[str, Type[BaseAnalysisTabWidget]]" = {}


class TabRegistry(QObjectType):

    """
    Analysis tab registry metaclass.  This registers tabs to be used both for
    populating the content of the "choose analysis" dialog and also for
    saving tab/workspace info.
    """

    def __new__(cls, *args, **kwargs):
        classdef = super().__new__(cls, *args, **kwargs)

        clsname = args[0]
        attributedict = args[2]

        # Only add concrete tabs with all required fields (skip base classes)
        # to the tab registry
        for k in TAB_REQUIRED_CLASSVARS:
            if k not in attributedict:
                return classdef

        TAB_REGISTRY[clsname] = classdef

        return classdef


# pylint: disable=invalid-metaclass
class BaseAnalysisTabWidget(QtWidgets.QScrollArea, metaclass=TabRegistry):

    """
    Base class for application top-level analysis tabs.

    Includes an optional frame for criteria.  Store the result widget at in
    the "results" attribute and it is added to the layout correctly.
    """

    criteria: "Tuple[CriteriaWidget, ...]"
    mlsonly: bool
    perm_map: "PermissionMap"
    section: AnalysisSection
    tab_title = "Title not set!"

    def __init__(self, enable_criteria: bool = True,
                 parent: "Optional[QtWidgets.QWidget]" = None) -> None:

        super().__init__(parent)
        self.log: "Final" = logging.getLogger(self.__module__)

        #
        # configure scroll area
        #
        self.setSizeAdjustPolicy(QtWidgets.QAbstractScrollArea.AdjustToContents)
        self.setWidgetResizable(True)
        self.setAttribute(QtCore.Qt.WidgetAttribute.WA_DeleteOnClose)

        #
        # Create top-level widget for the scroll area
        #
        self.top_widget = QtWidgets.QWidget(self)
        self.top_widget.setAttribute(QtCore.Qt.WidgetAttribute.WA_DeleteOnClose)

        # size policy for tab contents
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Minimum,
                                           QtWidgets.QSizePolicy.Policy.Minimum)
        sizePolicy.setHorizontalStretch(1)
        sizePolicy.setVerticalStretch(1)

        self.top_widget.setSizePolicy(sizePolicy)
        self.setWidget(self.top_widget)

        #
        # Create top level layout
        #
        self.top_layout = QtWidgets.QGridLayout(self.top_widget)
        self.top_layout.setContentsMargins(6, 6, 6, 6)
        self.top_layout.setSpacing(3)

        # title and "show" checkboxes
        title = QtWidgets.QLabel(self.top_widget)
        title.setText(self.tab_title)
        title.setObjectName("title")
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Preferred,
                                           QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(title.sizePolicy().hasHeightForWidth())
        title.setSizePolicy(sizePolicy)
        self.top_layout.addWidget(title, 0, 0)

        # spacer between title and "show:"
        spacerItem = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Policy.Expanding,
                                           QtWidgets.QSizePolicy.Policy.Minimum)
        self.top_layout.addItem(spacerItem, 0, 1)

        # "show" label
        label_2 = QtWidgets.QLabel(self.top_widget)
        label_2.setText("Show:")
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Preferred,
                                           QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(label_2.sizePolicy().hasHeightForWidth())
        label_2.setSizePolicy(sizePolicy)
        self.top_layout.addWidget(label_2, 0, 2)

        if enable_criteria:
            # criteria expander checkbox
            self.criteria_expander = QtWidgets.QCheckBox(self.top_widget)
            self.criteria_expander.setChecked(CRITERIA_DEFAULT_CHECKED)
            self.criteria_expander.setToolTip(
                "Show or hide the search criteria (no settings are lost)")
            self.criteria_expander.setWhatsThis(
                """
                <b>Show or hide the search criteria.</b>

                <p>No settings are lost if the criteria is hidden.</p>
                """)
            self.criteria_expander.setText("Criteria")
            self.top_layout.addWidget(self.criteria_expander, 0, 3)

        # notes expander checkbox
        self.notes_expander = QtWidgets.QCheckBox(self.top_widget)
        self.notes_expander.setSizePolicy(sizePolicy)
        self.notes_expander.setToolTip("Show or hide the notes.")
        self.notes_expander.setWhatsThis(
            """
            <b>Show or hide the notes field.</b>

            <p>No notes are lost if the notes are hidden.</p>
            """)
        self.notes_expander.setText("Notes")
        self.notes_expander.setChecked(NOTES_DEFAULT_CHECKED)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Minimum,
                                           QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(1)
        sizePolicy.setHeightForWidth(self.notes_expander.sizePolicy().hasHeightForWidth())
        self.top_layout.addWidget(self.notes_expander, 0, 4)

        if enable_criteria:
            # criteria frame
            self.criteria_frame = QtWidgets.QFrame(self.top_widget)
            sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Preferred,
                                               QtWidgets.QSizePolicy.Policy.Preferred)
            sizePolicy.setHorizontalStretch(0)
            sizePolicy.setVerticalStretch(1)
            sizePolicy.setHeightForWidth(self.criteria_frame.sizePolicy().hasHeightForWidth())
            self.criteria_frame.setSizePolicy(sizePolicy)
            self.criteria_frame.setFrameShape(QtWidgets.QFrame.StyledPanel)
            self.criteria_frame.setFrameShadow(QtWidgets.QFrame.Raised)
            self.criteria_frame.setVisible(CRITERIA_DEFAULT_CHECKED)
            self.criteria_expander.toggled.connect(self.criteria_frame.setVisible)

            self.criteria_frame_layout = QtWidgets.QGridLayout(self.criteria_frame)
            self.criteria_frame_layout.setContentsMargins(6, 6, 6, 6)
            self.criteria_frame_layout.setSpacing(3)
            self.top_layout.addWidget(self.criteria_frame, 1, 0, 1, 5)

            # Button box at the bottom of the criteria frame.  This must be
            # added to self.criteria_frame_layout by the subclasses, as the
            # placement is dependent on the criteria widget layout.
            self.buttonBox = QtWidgets.QDialogButtonBox(self.criteria_frame)
            self.run_button = QtWidgets.QPushButton(
                self.style().standardIcon(QtWidgets.QStyle.StandardPixmap.SP_ArrowRight),
                "Run",
                self.buttonBox)
            self.run_button.clicked.connect(self.run)
            self.buttonBox.addButton(self.run_button, QtWidgets.QDialogButtonBox.AcceptRole)

        # notes pane
        self.notes = QtWidgets.QTextEdit(self.top_widget)
        self.notes.setToolTip("Optionally enter notes here.")
        self.notes.setWhatsThis(
            """
            <b>Query Notes</b>

            <p>Optionally enter notes about the query and results here.  The
            notes are saved with tab and workspace data.</p>
            """
        )
        self.notes.setPlaceholderText("Enter notes here.")
        self.notes.setVisible(NOTES_DEFAULT_CHECKED)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Minimum,
                                           QtWidgets.QSizePolicy.Policy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(1)
        sizePolicy.setHeightForWidth(self.notes.sizePolicy().hasHeightForWidth())
        self.notes.setSizePolicy(sizePolicy)
        self.top_layout.addWidget(self.notes, 3, 0, 1, 5)
        self.notes_expander.toggled.connect(self.notes.setVisible)

        QtCore.QMetaObject.connectSlotsByName(self.top_widget)
        QtCore.QMetaObject.connectSlotsByName(self)

    @property
    def results(self) -> QtWidgets.QWidget:
        return self._results_widget

    @results.setter
    def results(self, widget: QtWidgets.QWidget) -> None:
        self.top_layout.addWidget(widget, 2, 0, 1, 5)
        self._results_widget = widget

    def run(self) -> None:
        raise NotImplementedError

    def query_completed(self, count: int) -> None:
        raise NotImplementedError

    def query_failed(self, message: str) -> None:
        raise NotImplementedError

    #
    # Workspace methods
    #

    def save(self) -> "Dict":
        """Return a dictionary of settings for this tab."""
        with suppress(AttributeError):  # handle criteria-less tabs
            errors = [c for c in self.criteria if c.has_errors]
            if errors:
                raise TabFieldError("Cannot save due to errors in the criteria.")

        settings: "Dict[str, Union[str, bool, List[str]]]" = {}
        settings[SETTINGS_SHOW_NOTES] = self.notes_expander.isChecked()
        settings[SETTINGS_NOTES] = self.notes.toPlainText()

        with suppress(AttributeError):
            settings[SETTINGS_SHOW_CRITERIA] = self.criteria_expander.isChecked()

        with suppress(AttributeError):
            for w in self.criteria:
                w.save(settings)

        return settings

    def load(self, settings: "Dict") -> None:
        """Load a dictionary of settings."""
        with suppress(AttributeError):  # handle criteria-less tabs
            for w in self.criteria:
                w.load(settings)

        with suppress(KeyError):
            self.notes.setText(str(settings[SETTINGS_NOTES]))

        with suppress(KeyError):
            self.notes_expander.setChecked(settings[SETTINGS_SHOW_NOTES])

        with suppress(KeyError, AttributeError):
            self.criteria_expander.setChecked(settings[SETTINGS_SHOW_CRITERIA])


class TableResultTabWidget(BaseAnalysisTabWidget):

    """
    Application top-level analysis tab that provides a QTabWidget with tabs for results
    in a table and in raw text form.
    """

    # TODO get signals to disable the run button if there are criteria errors.

    def __init__(self, query: "PolicyQuery", enable_criteria: bool = True,
                 parent: "Optional[QtWidgets.QWidget]" = None) -> None:

        super().__init__(enable_criteria=enable_criteria, parent=parent)
        self.query: "Final[PolicyQuery]" = query

        # results as 2 tab
        self.results = QtWidgets.QTabWidget(self.top_widget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Preferred,
                                           QtWidgets.QSizePolicy.Policy.MinimumExpanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(2)
        sizePolicy.setHeightForWidth(self.results.sizePolicy().hasHeightForWidth())
        self.results.setSizePolicy(sizePolicy)

        # create result tab 1
        self.table_results = SEToolsTableView(self.results)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Preferred,
                                           QtWidgets.QSizePolicy.Policy.MinimumExpanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.table_results.sizePolicy().hasHeightForWidth())
        self.table_results.setSizePolicy(sizePolicy)
        self.table_results.setSizeAdjustPolicy(QtWidgets.QAbstractScrollArea.AdjustIgnored)
        self.table_results.setAlternatingRowColors(True)
        self.table_results.setSortingEnabled(True)
        self.table_results.setWhatsThis(
            "<b>This tab has the table-based results of the query.</b>")
        self.results.addTab(self.table_results, "Results")
        self.results.setTabWhatsThis(
            0,
            "<b>This tab has the table-based results of the query.</b>")

        # Set up filter proxy. Subclasses must set the table_results_model
        # property to fully set this up.
        self.sort_proxy = QtCore.QSortFilterProxyModel(self.table_results)
        self.table_results.setModel(self.sort_proxy)
        self.table_results.sortByColumn(0, QtCore.Qt.SortOrder.AscendingOrder)

        # create result tab 2
        self.raw_results = QtWidgets.QPlainTextEdit(self.results)
        self.raw_results.setObjectName("raw_results")
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Preferred,
                                           QtWidgets.QSizePolicy.Policy.MinimumExpanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.raw_results.sizePolicy().hasHeightForWidth())
        self.raw_results.setSizePolicy(sizePolicy)
        self.raw_results.setDocumentTitle("")
        self.raw_results.setLineWrapMode(QtWidgets.QPlainTextEdit.LineWrapMode.NoWrap)
        self.raw_results.setReadOnly(True)
        self.raw_results.setWhatsThis("<b>This tab has plain text results of the query.</b>")
        self.results.addTab(self.raw_results, "Raw Results")
        self.results.setTabWhatsThis(1, "<b>This tab has plain text results of the query.</b>")
        self.results.setCurrentIndex(0)

        # set up processing thread
        self.processing_thread = QtCore.QThread(self.top_widget)

        # create a "busy, please wait" dialog
        self.busy = QtWidgets.QProgressDialog(self.top_widget)
        self.busy.setModal(True)
        self.busy.setRange(0, 0)
        self.busy.setMinimumDuration(0)
        self.busy.canceled.connect(self.processing_thread.requestInterruption)
        self.busy.reset()

        # Use INFO messages from the query to update the progress dialog
        self.handler = LogHandlerToSignal()
        self.handler.message.connect(self.busy.setLabelText)
        logging.getLogger(self.query.__module__).addHandler(self.handler)

    def __del__(self):
        with suppress(RuntimeError):
            self.processing_thread.quit()
            self.processing_thread.wait(5000)

        logging.getLogger(self.query.__module__).removeHandler(self.handler)

    @property
    def table_results_model(self) -> "SEToolsTableModel":
        return cast("SEToolsTableModel", self.sort_proxy.sourceModel())

    @table_results_model.setter
    def table_results_model(self, model: "SEToolsTableModel") -> None:
        self.sort_proxy.setSourceModel(model)

        self.worker = QueryResultsUpdater(self.query, model)
        self.worker.moveToThread(self.processing_thread)
        self.worker.raw_line.connect(self.raw_results.appendPlainText)
        self.worker.finished.connect(self.query_completed)
        self.worker.finished.connect(self.processing_thread.quit)
        self.worker.failed.connect(self.query_failed)
        self.worker.failed.connect(self.processing_thread.quit)
        self.processing_thread.started.connect(self.worker.update)

    #
    # Start/end of processing
    #

    def run(self) -> None:
        """Start processing query."""
        errors = [c for c in self.criteria if c.has_errors]
        if errors:
            QtWidgets.QMessageBox.critical(
                self, "Address criteria errors",
                "Cannot run due to errors in the criteria.",
                QtWidgets.QMessageBox.StandardButton.Ok)
            return

        self.busy.setLabelText("Processing query...")
        self.busy.show()
        self.raw_results.clear()
        self.processing_thread.start()

    def query_completed(self, count: int) -> None:
        """Query completed."""
        self.log.debug(f"{count} result(s) found.")
        self.setStatusTip(f"{count} result(s) found.")

        # update sizes/location of result displays
        if not self.busy.wasCanceled():
            self.busy.setLabelText("Resizing the result table's columns; GUI may be unresponsive")
            self.busy.repaint()
            self.table_results.resizeColumnsToContents()
            # If the permissions column width is too long, pull back
            # to a reasonable size
            header = self.table_results.horizontalHeader()
            if header.sectionSize(4) > 400:
                header.resizeSection(4, 400)

        if not self.busy.wasCanceled():
            self.busy.setLabelText("Resizing the result table's rows; GUI may be unresponsive")
            self.busy.repaint()
            self.table_results.resizeRowsToContents()

        if not self.busy.wasCanceled():
            self.busy.setLabelText("Moving the raw result to top; GUI may be unresponsive")
            self.busy.repaint()
            self.raw_results.moveCursor(QtGui.QTextCursor.MoveOperation.Start)

        self.busy.reset()

    def query_failed(self, message: str) -> None:
        self.busy.reset()
        self.setStatusTip(f"Error: {message}.")

        QtWidgets.QMessageBox.critical(
            self, "Error", message, QtWidgets.QMessageBox.StandardButton.Ok)


if __name__ == '__main__':
    import sys
    import warnings
    import setools

    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s|%(levelname)s|%(name)s|%(message)s')
    warnings.simplefilter("default")

    q = setools.TERuleQuery(setools.SELinuxPolicy())

    app = QtWidgets.QApplication(sys.argv)
    widget1 = BaseAnalysisTabWidget()
    widget1.show()
    widget2 = BaseAnalysisTabWidget(enable_criteria=False)
    widget2.show()
    widget3 = TableResultTabWidget(q)
    widget3.show()
    rc = app.exec_()
    sys.exit(rc)
