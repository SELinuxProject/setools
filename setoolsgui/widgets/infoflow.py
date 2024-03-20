# SPDX-License-Identifier: LGPL-2.1-only

from contextlib import suppress
import typing

from PyQt6 import QtCore, QtWidgets
import setools

from . import criteria, tab
from .excludetypes import ExcludeTypes
from .helpdialog import HtmlHelpDialog
from .permmap import PermissionMapEditor

DEFAULT_DEPTH_LIMIT: typing.Final[int] = 3
MIN_DEPTH_LIMIT: typing.Final[int] = 1

DEFAULT_MIN_PERM_WT: typing.Final[int] = 3
MIN_MIN_PERM_WT: typing.Final[int] = setools.PermissionMap.MIN_WEIGHT
MAX_MIN_PERM_WT: typing.Final[int] = setools.PermissionMap.MAX_WEIGHT

DEFAULT_RESULT_LIMIT: typing.Final[int] = 20
MIN_RESULT_LIMIT: typing.Final[int] = 1

SETTINGS_SOURCE: typing.Final[str] = "source"
SETTINGS_TARGET: typing.Final[str] = "target"
SETTINGS_MODE: typing.Final[str] = "mode"
SETTINGS_MIN_WEIGHT: typing.Final[str] = "min_weight"
SETTINGS_RESULT_LIMIT: typing.Final[str] = "result_limit"
SETTINGS_DEPTH_LIMIT: typing.Final[str] = "depth_limit"
SETTINGS_EXCLUDE_TYPES: typing.Final[str] = "exclude_types"

HELP_PAGE: typing.Final[str] = "widgets/infoflow.html"


class InfoFlowAnalysisTab(tab.DirectedGraphResultTab[setools.InfoFlowAnalysis,
                                                     setools.InfoFlowStep | setools.InfoFlowPath,
                                                     setools.Type]):

    """An information flow analysis."""

    section = tab.AnalysisSection.Analysis
    tab_title = "Information Flow Analysis"
    mlsonly = False

    def __init__(self, policy: setools.SELinuxPolicy, /, *,
                 parent: QtWidgets.QWidget | None = None) -> None:

        permmap = setools.PermissionMap()
        permmap.map_policy(policy)

        super().__init__(setools.InfoFlowAnalysis(policy, permmap),
                         enable_criteria=True, parent=parent)

        self.setWhatsThis("<b>Information flow analysis of an SELinux policy.</b>")

        #
        # Set up criteria widgets
        #
        src = criteria.TypeName("Source Type", self.query, SETTINGS_SOURCE,
                                enable_regex=False,
                                enable_indirect=False,
                                required=True,
                                parent=self.criteria_frame)
        src.setToolTip("The source type of the analysis.")
        src.setWhatsThis(
            """
            <p>For <i>shortest path</i> and <i>all paths</i> analyses, this
            this is the source type of the analysis.</p>

            <p>For <i>flows out</i> analysis, the analysis will return the
            information flows out of this type.</p>

            <p>This is not used for <i>flows in</i> analysis.
            """)

        #
        # Configure mode frame
        #
        modeframe = InfoFlowMode(self.query, parent=self)
        modeframe.selectionChanged.connect(self._apply_mode_change)

        #
        # Configure target type
        #
        dst = criteria.TypeName("Target Type", self.query, SETTINGS_TARGET,
                                enable_regex=False,
                                enable_indirect=False,
                                required=True,
                                parent=self.criteria_frame)
        dst.setToolTip("The target type of the analysis.")
        dst.setWhatsThis(
            """
            <p>For <i>shortest path</i> and <i>all paths</i> analyses, this
            this is the target type of the analysis.</p>

            <p>This is not used for <i>flows out</i> analysis.

            <p>For <i>flows in</i> analysis, the analysis will return the
            information flows into this type.</p>
            """)

        #
        # Configure options frame
        #
        optframe = InfoFlowOptions(self.query, parent=self.criteria_frame)
        optframe.result_limit_changed.connect(self._apply_result_limit)
        self._apply_result_limit()

        #
        # Set up tree view
        #

        # Disable source/target criteria based on info flow in/out
        modeframe.criteria[setools.InfoFlowAnalysis.Mode.FlowsOut].toggled.connect(dst.setDisabled)
        modeframe.criteria[setools.InfoFlowAnalysis.Mode.FlowsIn].toggled.connect(src.setDisabled)

        #
        # Add help button
        #
        self.buttonBox.addButton("Help", QtWidgets.QDialogButtonBox.ButtonRole.HelpRole)
        self.buttonBox.helpRequested.connect(self._show_help)

        #
        # Final setup
        #

        # ensure the mode is properly reflected
        self._apply_mode_change(self.query.mode)

        # Add widgets to layout
        self.criteria_frame_layout.addWidget(src, 1, 0, 2, 1)
        self.criteria_frame_layout.addWidget(modeframe, 0, 1, 2, 1)
        self.criteria_frame_layout.addWidget(dst, 1, 2, 2, 1)
        self.criteria_frame_layout.addWidget(optframe, 2, 1, 2, 1)
        self.criteria_frame_layout.addWidget(self.buttonBox, 4, 0, 1, 3)

        # Save widget references
        self.criteria = (src, dst, modeframe, optframe)

        # final config for DirectedGraphResultTab widgets
        self.tree_results.setHeaderLabel("Type")
        self.browser_worker.render = InfoFlowAnalysisTab._browser_entry_prep

    def _add_root_item(self) -> QtWidgets.QTreeWidgetItem | None:
        """Results completed, add top level item if applicable."""
        root: setools.Type | None
        query = self.browser_worker.query
        match query.mode:
            case setools.InfoFlowAnalysis.Mode.FlowsIn:
                root = query.target
            case setools.InfoFlowAnalysis.Mode.FlowsOut:
                root = query.source
            case _:
                root = None

        item: QtWidgets.QTreeWidgetItem | None = None
        if root:
            self.log.debug(f"Adding tree root item {root}")
            item = self._create_browser_item(root)
            self.tree_results.addTopLevelItem(item)
            self.tree_results.setCurrentItem(item)
            self.tree_results.expandItem(item)
        else:
            assert query.mode not in self.query.DIRECT_MODES, \
                f"No tree root item to add for {query.mode=}, " \
                "this is an SETools bug."
            self.log.debug("No tree root item to add.")

        return item

    def _apply_mode_change(self, mode: setools.InfoFlowAnalysis.Mode) -> None:
        """Reconfigure after an analysis mode change."""
        # Only enable tree browser for flows in/out mode.  Set the correct
        # renderer based on the mode.
        self.log.debug(f"Handling mode change to {mode}.")
        results = typing.cast(QtWidgets.QTabWidget, self.results)
        if mode in self.query.DIRECT_MODES:
            results.setTabEnabled(tab.DirectedGraphResultTab.ResultTab.Tree, True)
            self.worker.render = InfoFlowAnalysisTab.render_direct_path
        else:
            results.setTabEnabled(tab.DirectedGraphResultTab.ResultTab.Tree, False)
            self.worker.render = InfoFlowAnalysisTab.render_transitive_path

    def _apply_result_limit(self, value: int = DEFAULT_RESULT_LIMIT) -> None:
        """Apply result limit change."""
        assert isinstance(self.query, setools.InfoFlowAnalysis)  # type narrowing
        self.log.debug(f"Setting result limit to {value} flows.")
        self.worker.result_limit = value

    @staticmethod
    def _browser_entry_prep(query: setools.InfoFlowAnalysis,
                            flow: setools.InfoFlowStep,
                            ) -> tuple[setools.Type, setools.InfoFlowStep]:
        """Prepare the browser worker for the query."""
        child: setools.Type
        match query.mode:
            case setools.InfoFlowAnalysis.Mode.FlowsIn:
                child = flow.source
            case setools.InfoFlowAnalysis.Mode.FlowsOut:
                child = flow.target
            case _:
                raise ValueError(f"Invalid mode {query.mode=}, this is an SETools bug.")

        return child, flow

    def _populate_children(self, item: QtWidgets.QTreeWidgetItem) -> None:
        obj: setools.Type = item.data(0, self.ItemData.PolicyObject)
        query = self.browser_worker.query
        assert query.mode in query.DIRECT_MODES, \
            f"Invalid browser mode {query.mode=}, this is an SETools bug."
        self.log.debug(f"Populating children of {obj}")

        # reconfigure browser worker's query for this item
        match query.mode:
            case setools.InfoFlowAnalysis.Mode.FlowsIn:
                query.target = obj
            case setools.InfoFlowAnalysis.Mode.FlowsOut:
                query.source = obj

        self.browser_thread.start()

    def _show_help(self) -> None:
        """Show help dialog."""
        HtmlHelpDialog.from_package_file("Information Flow Analysis Help",
                                         HELP_PAGE,
                                         parent=self).open()

    def handle_permmap_change(self, permmap: setools.PermissionMap) -> None:
        self.log.debug(f"Applying updated permission map {permmap}")
        self.query.perm_map = permmap

    @staticmethod
    def render_direct_path(count: int, step: setools.InfoFlowStep) -> str:
        """Render text representation of flows in/out results."""
        return f"Flow {count}: {step:full}\n"

    @staticmethod
    def render_transitive_path(count: int, path: setools.InfoFlowPath) -> str:
        """Render text representation of all/shortest paths results."""
        lines = [f"Flow {count}:"]
        for stepnum, step in enumerate(path, start=1):
            lines.append(f"  Step {stepnum}: {step:full}\n")
        return "\n".join(lines)


class InfoFlowMode(criteria.RadioEnumWidget[setools.InfoFlowAnalysis.Mode]):

    """Information flow analysis mode radio buttons."""

    def __init__(self, query: setools.InfoFlowAnalysis,
                 parent: QtWidgets.QWidget | None = None) -> None:

        # colspan 2 so the below spinbox fits better with the radio button.
        super().__init__("Analysis Mode", query, SETTINGS_MODE, setools.InfoFlowAnalysis.Mode,
                         colspan=2, parent=parent)

        # Add all paths steps to mode widget.
        self.depth_limit = QtWidgets.QSpinBox(self)
        self.depth_limit.valueChanged.connect(self._apply_depth_limit)
        self.depth_limit.setSuffix(" steps")
        self.depth_limit.setMinimum(MIN_DEPTH_LIMIT)
        self.depth_limit.setValue(DEFAULT_DEPTH_LIMIT)
        # when switching between modes, the depth limit is forced to 1 if not
        # using all paths.  This is the previous depth limit value that is
        # restored when going back to all paths mode.
        self.last_depth_limit: int = DEFAULT_DEPTH_LIMIT

        # get layout location of all paths option
        all_path_index = self.top_layout.indexOf(
            self.criteria[setools.InfoFlowAnalysis.Mode.AllPaths])
        row, col, _, _ = self.top_layout.getItemPosition(all_path_index)
        assert row is not None and col is not None, \
            "Layout position is None, this is an SETools bug."  # type narrowing
        assert row >= 0 and col >= 0, \
            f"Invalid layout position, this is an SETools bug. ({row},{col})"
        # add steps spin box in the next column of the radio button
        self.top_layout.addWidget(self.depth_limit, row, col + 1, 1, 1)

        # set path steps to enable only if the corresponding mode is selected.
        # it starts disabled since shortest paths is the default option.
        self._apply_depth_limit_from_mode_change(False)
        self.criteria[setools.InfoFlowAnalysis.Mode.AllPaths].toggled.connect(
            self._apply_depth_limit_from_mode_change)

    def _apply_depth_limit(self, value: int = DEFAULT_DEPTH_LIMIT) -> None:
        """Apply the value of the all paths spinbox to the query."""
        assert isinstance(self.query, setools.InfoFlowAnalysis)  # type narrowing
        self.log.debug(f"All paths max steps to {value} steps.")
        self.query.depth_limit = value

    def _apply_depth_limit_from_mode_change(self, value: bool) -> None:
        """After a mode change, force the depth limit to 1 if not using all flows."""
        if value:  # All paths mode is enabled
            self.depth_limit.setValue(self.last_depth_limit)
            self.depth_limit.setEnabled(True)
        else:  # Another mode is selected
            self.last_depth_limit = self.depth_limit.value()
            self.depth_limit.setValue(MIN_DEPTH_LIMIT)
            self.depth_limit.setEnabled(False)

    def save(self, settings: dict) -> None:
        super().save(settings)
        settings[SETTINGS_DEPTH_LIMIT] = self.depth_limit.value()

    def load(self, settings: dict) -> None:
        with suppress(KeyError):
            self.depth_limit.setValue(settings[SETTINGS_DEPTH_LIMIT])

        super().load(settings)


class InfoFlowOptions(criteria.CriteriaWidget):

    """
    Infoflow analysis options widget.

    Presents the options:
    * Minimum permission weight
    * Limit number of results
    * Exclude types button
    * Exclude permissions/classes button
    """

    has_errors: typing.Final[bool] = False
    result_limit_changed = QtCore.pyqtSignal(int)

    def __init__(self, query: setools.InfoFlowAnalysis,
                 parent: QtWidgets.QWidget | None = None) -> None:

        super().__init__("Options", query, "", parent=parent)

        self.top_layout = QtWidgets.QFormLayout(self)
        self.top_layout.setLabelAlignment(QtCore.Qt.AlignmentFlag.AlignRight)

        self.min_weight = QtWidgets.QSpinBox(self)
        self.min_weight.valueChanged.connect(self._apply_min_weight)
        self.min_weight.setValue(DEFAULT_MIN_PERM_WT)
        self.min_weight.setMinimum(MIN_MIN_PERM_WT)
        self.min_weight.setMaximum(MAX_MIN_PERM_WT)
        self.top_layout.addRow(QtWidgets.QLabel("Minimum permission weight:", self),
                               self.min_weight)

        self.result_limit = QtWidgets.QSpinBox(self)
        self.result_limit.valueChanged.connect(self.result_limit_changed)
        self.result_limit.setValue(DEFAULT_RESULT_LIMIT)
        self.result_limit.setMinimum(MIN_RESULT_LIMIT)
        self.top_layout.addRow(QtWidgets.QLabel("Limit results:", self),
                               self.result_limit)

        self.edit_excluded_types = QtWidgets.QPushButton("Edit...", self)
        self.edit_excluded_types.clicked.connect(self._start_type_exclude)
        self.top_layout.addRow(QtWidgets.QLabel("Excluded types:", self),
                               self.edit_excluded_types)

        self.edit_excluded_perms = QtWidgets.QPushButton("Edit...", self)
        self.edit_excluded_perms.clicked.connect(self._start_permmap_exclude)
        self.top_layout.addRow(QtWidgets.QLabel("Excluded permissions:", self),
                               self.edit_excluded_perms)

    def _apply_min_weight(self, value: int) -> None:
        """Apply minimum perm weight to the query."""
        assert isinstance(self.query, setools.InfoFlowAnalysis)  # type narrowing
        self.log.debug(f"Setting min permission weight to {value}")
        self.query.min_weight = value

    def _apply_permmap(self, new_map: setools.PermissionMap) -> None:
        assert isinstance(self.query, setools.InfoFlowAnalysis)  # type narrowing
        self.log.debug("Applying updated permission map.")
        self.query.perm_map = new_map

    def _start_permmap_exclude(self) -> None:
        w = PermissionMapEditor(self.query.perm_map, edit=False, parent=self)
        w.apply_permmap.connect(self._apply_permmap)
        w.open()

    def _start_type_exclude(self) -> None:
        ExcludeTypes(self.query, parent=self).open()

    def save(self, settings: dict) -> None:
        assert isinstance(self.query, setools.InfoFlowAnalysis)  # type narrowing
        super().save(settings)
        settings[SETTINGS_MIN_WEIGHT] = self.min_weight.value()
        settings[SETTINGS_RESULT_LIMIT] = self.result_limit.value()
        settings[SETTINGS_EXCLUDE_TYPES] = [str(t) for t in self.query.exclude]
        # TODO: permmap with enable/disable states

    def load(self, settings: dict) -> None:
        assert isinstance(self.query, setools.InfoFlowAnalysis)  # type narrowing
        with suppress(KeyError):
            self.min_weight.setValue(settings[SETTINGS_MIN_WEIGHT])

        with suppress(KeyError):
            self.result_limit.setValue(settings[SETTINGS_RESULT_LIMIT])

        with suppress(KeyError):
            self.query.exclude = settings[SETTINGS_EXCLUDE_TYPES]

        # TODO: perm map
        super().load(settings)


if __name__ == '__main__':
    import sys
    import logging
    import pprint
    import warnings

    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s|%(levelname)s|%(name)s|%(message)s')
    warnings.simplefilter("default")

    app = QtWidgets.QApplication(sys.argv)
    mw = QtWidgets.QMainWindow()
    widget = InfoFlowAnalysisTab(setools.SELinuxPolicy(), parent=mw)
    mw.setCentralWidget(widget)
    mw.resize(widget.size())
    whatsthis = QtWidgets.QWhatsThis.createAction(mw)
    mw.menuBar().addAction(whatsthis)  # type: ignore[union-attr]
    mw.setStatusBar(QtWidgets.QStatusBar(mw))
    mw.resize(1024, 768)
    mw.show()
    rc = app.exec()
    pprint.pprint(widget.save())
    sys.exit(rc)
