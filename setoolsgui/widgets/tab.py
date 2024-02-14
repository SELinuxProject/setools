# SPDX-License-Identifier: LGPL-2.1-only

from contextlib import suppress
import enum
import logging
import typing

from PyQt6 import QtCore, QtGui, QtWidgets
import setools

from . import criteria, exception, models, util, views
from .queryupdater import QueryResultsUpdater

# workspace settings keys
SETTINGS_NOTES: typing.Final[str] = "notes"
SETTINGS_SHOW_NOTES: typing.Final[str] = "show_notes"
SETTINGS_SHOW_CRITERIA: typing.Final[str] = "show_criteria"

# Show criteria default setting (checked)
CRITERIA_DEFAULT_CHECKED: typing.Final[bool] = True
# Show notes default setting (unchecked)
NOTES_DEFAULT_CHECKED: typing.Final[bool] = False

TAB_REGISTRY: typing.Final[dict[str, type["BaseAnalysisTabWidget"]]] = {}

__all__ = ("AnalysisSection", "BaseAnalysisTabWidget", "TableResultTabWidget",
           "DirectedGraphResultTab", "TAB_REGISTRY")


class AnalysisSection(enum.Enum):

    """Groupings of analysis tabs"""

    Analysis = 1
    Components = 2
    General = 3
    Labeling = 4
    Other = 5
    Rules = 6


class TabRegistry(models.typing.MetaclassFix):

    """
    Analysis tab registry metaclass.  This registers tabs to be used both for
    populating the content of the "choose analysis" dialog and also for
    saving tab/workspace info.
    """

    def __new__(cls, *args, **kwargs):
        classdef = super().__new__(cls, *args, **kwargs)

        # Only add classes following the tab protocol to the tab registry.
        if isinstance(classdef, TabProtocol):
            clsname = args[0]
            TAB_REGISTRY[clsname] = classdef

        return classdef


@typing.runtime_checkable
class TabProtocol(typing.Protocol):

    """Protocol for tab widgets, in addition to standard Qt widget methods."""

    tab_title: str
    section: AnalysisSection
    mlsonly: bool

    def __init__(self, policy: setools.SELinuxPolicy, /, *,
                 parent: QtWidgets.QWidget | None = None) -> None:
        ...

    def handle_permmap_change(self, permmap: setools.PermissionMap) -> None:
        """Handle permission map changes."""
        ...

    def load(self, settings: dict) -> None:
        """Load a dictionary of settings."""
        ...

    def save(self) -> dict:
        """Return a dictionary of settings for this tab."""
        ...


#
# The below base classes have unused __init__ arguments to match the
# above protocol.
#

# pylint: disable=invalid-metaclass
class BaseAnalysisTabWidget(QtWidgets.QScrollArea, metaclass=TabRegistry):

    """
    Base class for application top-level analysis tabs.

    Includes an optional frame for criteria.  Store the result widget at in
    the "results" attribute and it is added to the layout correctly.
    """

    tab_title: typing.ClassVar[str] = "Title not set!"
    section: typing.ClassVar[AnalysisSection]
    mlsonly: typing.ClassVar[bool]

    criteria: tuple[criteria.criteria.CriteriaWidget, ...]
    perm_map: setools.PermissionMap

    def __init__(self, _, /, *,
                 enable_criteria: bool = True, enable_browser: bool = False,
                 parent: QtWidgets.QWidget | None = None) -> None:

        super().__init__(parent)
        self.log: typing.Final = logging.getLogger(self.__module__)

        #
        # configure scroll area
        #
        self.setSizeAdjustPolicy(QtWidgets.QAbstractScrollArea.SizeAdjustPolicy.AdjustToContents)
        self.setWidgetResizable(True)
        self.setAttribute(QtCore.Qt.WidgetAttribute.WA_DeleteOnClose)

        #
        # Create top-level widget for the scroll area
        #

        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Minimum,
                                           QtWidgets.QSizePolicy.Policy.Minimum)
        sizePolicy.setHorizontalStretch(1)
        sizePolicy.setVerticalStretch(1)

        # Create splitter
        self.top_widget = QtWidgets.QSplitter(self)
        self.top_widget.setOrientation(QtCore.Qt.Orientation.Horizontal)
        self.top_widget.setSizePolicy(sizePolicy)
        self.setWidget(self.top_widget)

        #
        # Build browser
        #
        if enable_browser:
            browser_sizing = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Minimum,
                                                   QtWidgets.QSizePolicy.Policy.Minimum)
            browser_sizing.setHorizontalStretch(0)
            browser_sizing.setVerticalStretch(0)

            # create browser
            self.browser = views.SEToolsListView(self.top_widget)
            self.browser.setSizePolicy(browser_sizing)
            self.top_widget.addWidget(self.browser)
            self.top_widget.setCollapsible(self.top_widget.indexOf(self.browser), True)

        #
        # Build analysis widget
        #
        self.analysis_widget = QtWidgets.QWidget(self.top_widget)
        self.analysis_widget.setSizePolicy(sizePolicy)
        self.top_widget.addWidget(self.analysis_widget)
        self.top_widget.setCollapsible(self.top_widget.indexOf(self.analysis_widget), False)

        #
        # Create analysis layout
        #
        self.analysis_layout = QtWidgets.QGridLayout(self.analysis_widget)
        self.analysis_layout.setContentsMargins(6, 6, 6, 6)
        self.analysis_layout.setSpacing(3)

        # title and "show" checkboxes
        title = QtWidgets.QLabel(self.analysis_widget)
        title.setText(self.tab_title)
        title.setObjectName("title")
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Preferred,
                                           QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(title.sizePolicy().hasHeightForWidth())
        title.setSizePolicy(sizePolicy)
        self.analysis_layout.addWidget(title, 0, 0)

        # spacer between title and "show:"
        spacerItem = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Policy.Expanding,
                                           QtWidgets.QSizePolicy.Policy.Minimum)
        self.analysis_layout.addItem(spacerItem, 0, 1)

        # "show" label
        label_2 = QtWidgets.QLabel(self.analysis_widget)
        label_2.setText("Show:")
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Preferred,
                                           QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(label_2.sizePolicy().hasHeightForWidth())
        label_2.setSizePolicy(sizePolicy)
        self.analysis_layout.addWidget(label_2, 0, 2)

        if enable_criteria:
            # criteria expander checkbox
            self.criteria_expander = QtWidgets.QCheckBox(self.analysis_widget)
            self.criteria_expander.setChecked(CRITERIA_DEFAULT_CHECKED)
            self.criteria_expander.setToolTip(
                "Show or hide the search criteria (no settings are lost)")
            self.criteria_expander.setWhatsThis(
                """
                <b>Show or hide the search criteria.</b>

                <p>No settings are lost if the criteria is hidden.</p>
                """)
            self.criteria_expander.setText("Criteria")
            self.analysis_layout.addWidget(self.criteria_expander, 0, 3)

        # notes expander checkbox
        self.notes_expander = QtWidgets.QCheckBox(self.analysis_widget)
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
        self.analysis_layout.addWidget(self.notes_expander, 0, 4)

        if enable_criteria:
            # criteria frame
            self.criteria_frame = QtWidgets.QFrame(self.analysis_widget)
            sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Preferred,
                                               QtWidgets.QSizePolicy.Policy.Preferred)
            sizePolicy.setHorizontalStretch(0)
            sizePolicy.setVerticalStretch(1)
            sizePolicy.setHeightForWidth(self.criteria_frame.sizePolicy().hasHeightForWidth())
            self.criteria_frame.setSizePolicy(sizePolicy)
            self.criteria_frame.setFrameShape(QtWidgets.QFrame.Shape.StyledPanel)
            self.criteria_frame.setFrameShadow(QtWidgets.QFrame.Shadow.Raised)
            self.criteria_frame.setVisible(CRITERIA_DEFAULT_CHECKED)
            self.criteria_expander.toggled.connect(self.criteria_frame.setVisible)

            self.criteria_frame_layout = QtWidgets.QGridLayout(self.criteria_frame)
            self.criteria_frame_layout.setContentsMargins(6, 6, 6, 6)
            self.criteria_frame_layout.setSpacing(3)
            self.analysis_layout.addWidget(self.criteria_frame, 1, 0, 1, 5)

            # Button box at the bottom of the criteria frame.  This must be
            # added to self.criteria_frame_layout by the subclasses, as the
            # placement is dependent on the criteria widget layout.
            self.buttonBox = QtWidgets.QDialogButtonBox(self.criteria_frame)
            self.run_button = QtWidgets.QPushButton(
                self.style().standardIcon(QtWidgets.QStyle.StandardPixmap.SP_ArrowRight),
                "Run",
                self.buttonBox)
            self.run_button.clicked.connect(self.run)
            self.buttonBox.addButton(self.run_button,
                                     QtWidgets.QDialogButtonBox.ButtonRole.AcceptRole)

        # notes pane
        self.notes = QtWidgets.QTextEdit(self.analysis_widget)
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
        self.analysis_layout.addWidget(self.notes, 3, 0, 1, 5)
        self.notes_expander.toggled.connect(self.notes.setVisible)

        QtCore.QMetaObject.connectSlotsByName(self.analysis_widget)
        QtCore.QMetaObject.connectSlotsByName(self)

    @property
    def results(self) -> QtWidgets.QWidget:
        return self._results_widget

    @results.setter
    def results(self, widget: QtWidgets.QWidget) -> None:
        self.analysis_layout.addWidget(widget, 2, 0, 1, 5)
        self._results_widget = widget

    def run(self) -> None:
        """Run the query."""
        raise NotImplementedError

    def query_completed(self, count: int) -> None:
        """Handle successful query completion."""
        raise NotImplementedError

    def query_failed(self, message: str) -> None:
        """Handle query failure."""
        raise NotImplementedError

    # @typing.override
    def style(self) -> QtWidgets.QStyle:
        """Type-narrowed style() method.  Always returns a QStyle."""
        style = super().style()
        assert style, "No style set, this is an SETools bug"  # type narrowing
        return style

    #
    # Workspace methods
    #
    def handle_permmap_change(self, permmap: setools.PermissionMap) -> None:
        """Handle permission map changes."""
        pass

    def save(self) -> dict:
        """Return a dictionary of settings for this tab."""
        with suppress(AttributeError):  # handle criteria-less tabs
            errors = [c for c in self.criteria if c.has_errors]
            if errors:
                raise exception.TabFieldError("Cannot save due to errors in the criteria.")

        settings = dict[str, str | bool | list[str]]()
        settings[SETTINGS_SHOW_NOTES] = self.notes_expander.isChecked()
        settings[SETTINGS_NOTES] = self.notes.toPlainText()

        with suppress(AttributeError):
            settings[SETTINGS_SHOW_CRITERIA] = self.criteria_expander.isChecked()

        with suppress(AttributeError):
            for w in self.criteria:
                w.save(settings)

        return settings

    def load(self, settings: dict) -> None:
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

    class ResultTab(enum.IntEnum):

        """
        Enumeration of result tabs.

        0-indexed to match the tab widget indexing.
        """

        Table = 0
        Text = 1

    def __init__(self, query: setools.PolicyQuery, /, *,
                 enable_criteria: bool = True, enable_browser: bool = False,
                 parent: QtWidgets.QWidget | None = None) -> None:

        super().__init__(query, enable_criteria=enable_criteria,
                         enable_browser=enable_browser, parent=parent)
        self.query: typing.Final = query

        # results as 2 tab
        self.results = QtWidgets.QTabWidget(self.analysis_widget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Preferred,
                                           QtWidgets.QSizePolicy.Policy.MinimumExpanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(2)
        sizePolicy.setHeightForWidth(self.results.sizePolicy().hasHeightForWidth())
        self.results.setSizePolicy(sizePolicy)

        # create result tab 1
        self.table_results = views.SEToolsTableView(self.results)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Preferred,
                                           QtWidgets.QSizePolicy.Policy.MinimumExpanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.table_results.sizePolicy().hasHeightForWidth())
        self.table_results.setSizePolicy(sizePolicy)
        self.table_results.setSizeAdjustPolicy(
            QtWidgets.QAbstractScrollArea.SizeAdjustPolicy.AdjustIgnored)
        self.table_results.setAlternatingRowColors(True)
        self.table_results.setSortingEnabled(True)
        self.table_results.setWhatsThis(
            "<b>This tab has the table-based results of the query.</b>")
        self.results.addTab(self.table_results, "Results")
        self.results.setTabWhatsThis(
            TableResultTabWidget.ResultTab.Table,
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
        self.results.setTabWhatsThis(TableResultTabWidget.ResultTab.Text,
                                     "<b>This tab has plain text results of the query.</b>")

        self.results.setCurrentIndex(TableResultTabWidget.ResultTab.Table)

        # set up processing thread
        self.processing_thread = QtCore.QThread(self.analysis_widget)

        # create a "busy, please wait" dialog
        self.busy = QtWidgets.QProgressDialog(self.analysis_widget)
        self.busy.setModal(True)
        self.busy.setRange(0, 0)
        self.busy.setMinimumDuration(0)
        self.busy.canceled.connect(self.processing_thread.requestInterruption)
        self.busy.reset()

    def __del__(self):
        with suppress(RuntimeError):
            self.processing_thread.quit()
            self.processing_thread.wait(5000)

    @property
    def table_results_model(self) -> models.SEToolsTableModel:
        """Return the table results model for this tab."""
        return typing.cast(models.SEToolsTableModel, self.sort_proxy.sourceModel())

    @table_results_model.setter
    def table_results_model(self, model: models.SEToolsTableModel) -> None:
        """Set the table results model for this tab and set up the processing thread for it."""
        self.sort_proxy.setSourceModel(model)

        self.worker = QueryResultsUpdater(self.query, table_model=model)
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
        errors = [c.title() for c in self.criteria if c.has_errors]
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

        # If the column widths are too long, pull back to a reasonable size
        header = self.table_results.horizontalHeader()
        assert header, "No header set, this is an SETools bug"  # type narrowing
        self.busy.setLabelText("Resizing very wide columns; GUI may be unresponsive")
        for i in range(header.count()):
            if header.sectionSize(i) > 400:
                header.resizeSection(i, 400)

            if self.busy.wasCanceled():
                break

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


DGA = typing.TypeVar("DGA", bound=setools.query.DirectedGraphAnalysis)


class DirectedGraphResultTab(BaseAnalysisTabWidget, typing.Generic[DGA]):

    """
    Application top-level analysis tab that provides a QTabWidget with tabs for results
    in a graph and in raw text form.
    """

    # TODO get signals to disable the run button if there are criteria errors.

    class ResultTab(enum.IntEnum):

        """
        Enumeration of result tabs.

        0-indexed to match the tab widget indexing.
        """

        Graph = 0
        Tree = 1
        Text = 2

    def __init__(self, query: DGA, /, *,
                 enable_criteria: bool = True,
                 parent: QtWidgets.QWidget | None = None) -> None:

        super().__init__(query, enable_criteria=enable_criteria, enable_browser=False,
                         parent=parent)
        self.query: typing.Final = query

        # Create tab widget
        self.results = QtWidgets.QTabWidget(self.analysis_widget)
        tw_sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Preferred,
                                              QtWidgets.QSizePolicy.Policy.MinimumExpanding)
        tw_sizePolicy.setHorizontalStretch(0)
        tw_sizePolicy.setVerticalStretch(2)
        tw_sizePolicy.setHeightForWidth(self.results.sizePolicy().hasHeightForWidth())
        self.results.setSizePolicy(tw_sizePolicy)

        #
        # Create size policy for tabs
        #
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Preferred,
                                           QtWidgets.QSizePolicy.Policy.MinimumExpanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.results.sizePolicy().hasHeightForWidth())

        #
        # Create graphical tab
        #
        self.graphical_scroll = QtWidgets.QScrollArea(self.results)
        self.graphical_scroll.setSizeAdjustPolicy(
            QtWidgets.QAbstractScrollArea.SizeAdjustPolicy.AdjustToContents)
        self.graphical_scroll.setWidgetResizable(True)
        self.results.addTab(self.graphical_scroll, "Graphical Results")

        image_size_policy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.MinimumExpanding,
                                                  QtWidgets.QSizePolicy.Policy.MinimumExpanding)
        image_size_policy.setHorizontalStretch(1)
        image_size_policy.setVerticalStretch(1)
        image_size_policy.setHeightForWidth(True)

        self.graphical_results = QtWidgets.QLabel(self.graphical_scroll)
        self.graphical_results.setObjectName("graphical_results")
        self.graphical_results.setSizePolicy(image_size_policy)
        self.graphical_results.setContextMenuPolicy(QtCore.Qt.ContextMenuPolicy.CustomContextMenu)
        self.graphical_results.customContextMenuRequested.connect(
            self._graphical_results_context_menu)
        self.graphical_scroll.setWidget(self.graphical_results)

        #
        # Create tree browser tab
        #
        self.tree_results = views.SEToolsTreeWidget(self.results)
        self.tree_results.setObjectName("tree_results")
        self.tree_results.setSizePolicy(sizePolicy)
        self.tree_results.setSizeAdjustPolicy(
            QtWidgets.QAbstractScrollArea.SizeAdjustPolicy.AdjustIgnored)
        self.tree_results.setAlternatingRowColors(True)
        self.tree_results.setSortingEnabled(True)
        self.tree_results.setWhatsThis(
            "<b>This tab has the tree-based results of the query.</b>")
        self.results.addTab(self.tree_results, "Tree Results")
        self.results.setTabWhatsThis(
            DirectedGraphResultTab.ResultTab.Tree,
            "<b>This tab has the tree-based results of the query.</b>")

        #
        # Create text result tab
        #
        self.raw_results = QtWidgets.QPlainTextEdit(self.results)
        self.raw_results.setObjectName("raw_results")
        self.raw_results.setSizePolicy(sizePolicy)
        self.raw_results.setDocumentTitle(f"{self.tab_title} Text Results")
        self.raw_results.setLineWrapMode(QtWidgets.QPlainTextEdit.LineWrapMode.NoWrap)
        self.raw_results.setReadOnly(True)
        self.raw_results.setWhatsThis("<b>This tab has plain text results of the query.</b>")
        self.results.addTab(self.raw_results, "Raw Results")
        self.results.setTabWhatsThis(DirectedGraphResultTab.ResultTab.Text,
                                     "<b>This tab has plain text results of the query.</b>")

        # set initial tab
        self.results.setCurrentIndex(DirectedGraphResultTab.ResultTab.Graph)

        # set up processing thread
        self.processing_thread = QtCore.QThread(self.analysis_widget)

        # create a "busy, please wait" dialog
        self.busy = QtWidgets.QProgressDialog(self.analysis_widget)
        self.busy.setModal(True)
        self.busy.setRange(0, 0)
        self.busy.setMinimumDuration(0)
        self.busy.canceled.connect(self.processing_thread.requestInterruption)
        self.busy.reset()

        # set up results worker
        self.worker = QueryResultsUpdater[DGA](self.query, graphics_buffer=self.graphical_results)
        self.worker.moveToThread(self.processing_thread)
        self.worker.raw_line.connect(self.raw_results.appendPlainText)
        self.worker.finished.connect(self.query_completed)
        self.worker.finished.connect(self.processing_thread.quit)
        self.worker.failed.connect(self.query_failed)
        self.worker.failed.connect(self.processing_thread.quit)
        self.processing_thread.started.connect(self.worker.update)

    def __del__(self):
        with suppress(RuntimeError):
            self.processing_thread.quit()
            self.processing_thread.wait(5000)

    @property
    def tree_results_model(self) -> models.SEToolsTableModel:
        return typing.cast(models.SEToolsTableModel, self.tree_results.model())

    @tree_results_model.setter
    def tree_results_model(self, model: models.SEToolsTableModel) -> None:
        self.tree_results.setModel(model)
        self.worker.table_model = model

    def _graphical_results_context_menu(self, pos: QtCore.QPoint) -> None:
        """Generate context menu for graphical results widget."""
        save_action = QtGui.QAction("Save As...", self.graphical_results)
        save_action.triggered.connect(self._save_graphical_results)

        menu = QtWidgets.QMenu(self.graphical_results)
        menu.setAttribute(QtCore.Qt.WidgetAttribute.WA_DeleteOnClose)
        menu.addActions((save_action,))
        menu.exec(self.graphical_results.mapToGlobal(pos))

    def _save_graphical_results(self) -> None:
        """Save the graphical results to a file."""
        with util.QMessageOnException("Error",
                                      "<b>Failed to save graphical results.</b>",
                                      log=self.log,
                                      parent=self):

            filename, _ = QtWidgets.QFileDialog.getSaveFileName(
                self, "Save graphical results", "", "PNG files (*.png);;All files (*)")

            if filename:
                if not self.graphical_results.pixmap().save(filename, format="PNG"):
                    # The save method does not raise an exception, so unfortunately
                    # there is no additional info to share with the user.
                    raise RuntimeError(f"Failed to save graphical results to {filename}.")

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

    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s|%(levelname)s|%(name)s|%(message)s')
    warnings.simplefilter("default")

    p = setools.SELinuxPolicy()
    q = setools.TERuleQuery(p)
    pmap = setools.PermissionMap()
    a = setools.InfoFlowAnalysis(p, pmap)

    app = QtWidgets.QApplication(sys.argv)
    mw = QtWidgets.QMainWindow()
    whatsthis = QtWidgets.QWhatsThis.createAction(mw)
    mw.menuBar().addAction(whatsthis)  # type: ignore[union-attr]
    mw.setStatusBar(QtWidgets.QStatusBar(mw))

    tw = QtWidgets.QTabWidget(mw)
    mw.setCentralWidget(tw)
    widget1 = BaseAnalysisTabWidget(None, parent=tw)
    tw.addTab(widget1, "BaseAnalysisTabWidget w/criteria")
    widget2 = BaseAnalysisTabWidget(None, enable_criteria=False, parent=tw)
    tw.addTab(widget2, "BaseAnalysisTabWidget w/o criteria")
    widget3 = TableResultTabWidget(q, parent=tw)
    tw.addTab(widget3, "TableResultTabWidget")
    widget4 = DirectedGraphResultTab(a, parent=tw)
    tw.addTab(widget4, "GraphResultTabWidget w/criteria")

    mw.resize(1024, 768)
    mw.show()
    rc = app.exec()
    sys.exit(rc)
