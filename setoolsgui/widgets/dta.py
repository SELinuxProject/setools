# SPDX-License-Identifier: LGPL-2.1-only

from contextlib import suppress
import typing

from PyQt6 import QtCore, QtWidgets
import setools

from . import criteria, tab
from .excludetypes import ExcludeTypes
from .helpdialog import HtmlHelpDialog

DEFAULT_DEPTH_LIMIT: typing.Final[int] = 3
MIN_DEPTH_LIMIT: typing.Final[int] = 1

DEFAULT_RESULT_LIMIT: typing.Final[int] = 20
MIN_RESULT_LIMIT: typing.Final[int] = 1

DEFAULT_REVERSE: typing.Final[bool] = False

SETTINGS_SOURCE: typing.Final[str] = "source"
SETTINGS_TARGET: typing.Final[str] = "target"
SETTINGS_MODE: typing.Final[str] = "mode"
SETTINGS_REVERSE: typing.Final[str] = "reverse"
SETTINGS_RESULT_LIMIT: typing.Final[str] = "result_limit"
SETTINGS_DEPTH_LIMIT: typing.Final[str] = "depth_limit"
SETTINGS_EXCLUDE_TYPES: typing.Final[str] = "exclude_types"

HELP_PAGE: typing.Final[str] = "widgets/dta.html"


class DomainTransitionAnalysisTab(tab.DirectedGraphResultTab[setools.DomainTransitionAnalysis]):

    """A domain transition analysis."""

    section = tab.AnalysisSection.Analysis
    tab_title = "Domain Transition Analysis"
    mlsonly = False

    def __init__(self, policy: setools.SELinuxPolicy, /, *,
                 parent: QtWidgets.QWidget | None = None) -> None:

        super().__init__(setools.DomainTransitionAnalysis(policy),
                         enable_criteria=True, parent=parent)

        self.setWhatsThis("<b>Domain transition analysis of an SELinux policy.</b>")

        #
        # Set up criteria widgets
        #
        src = criteria.TypeName("Source Domain", self.query, SETTINGS_SOURCE,
                                enable_regex=False,
                                enable_indirect=False,
                                required=True,
                                parent=self.criteria_frame)
        src.setToolTip("The source domain of the analysis.")
        src.setWhatsThis(
            """
            <p>For <i>shortest path</i> and <i>all paths</i> analyses, this
            this is the source domain of the analysis.</p>

            <p>For <i>transitions out</i> analysis, the analysis will return the
            information transitions out of this domain.</p>

            <p>This is not used for <i>transitions in</i> analysis.
            """)

        #
        # Configure mode frame
        #
        modeframe = DTAMode(self.query, parent=self)
        modeframe.selectionChanged.connect(self._apply_mode_change)

        #
        # Configure target domain
        #
        dst = criteria.TypeName("Target Domain", self.query, SETTINGS_TARGET,
                                enable_regex=False,
                                enable_indirect=False,
                                required=True,
                                parent=self.criteria_frame)
        dst.setToolTip("The target domain of the analysis.")
        dst.setWhatsThis(
            """
            <p>For <i>shortest path</i> and <i>all paths</i> analyses, this
            this is the target domain of the analysis.</p>

            <p>This is not used for <i>transitions out</i> analysis.

            <p>For <i>transitions in</i> analysis, the analysis will return the
            transitions into this domain.</p>
            """)

        #
        # Configure options frame
        #
        optframe = DTAOptions(self.query, parent=self.criteria_frame)
        optframe.result_limit_changed.connect(self._apply_result_limit)
        self._apply_result_limit()

        #
        # Set up tree view
        #

        # Disable source/target criteria based on info flow in/out
        modeframe.criteria[setools.DomainTransitionAnalysis.Mode.TransitionsOut].toggled.connect(
            dst.setDisabled)
        modeframe.criteria[setools.DomainTransitionAnalysis.Mode.TransitionsIn].toggled.connect(
            src.setDisabled)

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

        # Set result table's model
        # self.tree_results_model = models.MLSRuleTable(self.table_results)

    def _apply_mode_change(self, mode: setools.DomainTransitionAnalysis.Mode) -> None:
        """Reconfigure after an analysis mode change."""
        # Only enable tree browser for flows in/out mode.  Set the correct
        # renderer based on the mode.
        self.log.debug(f"Handling mode change to {mode}.")
        results = typing.cast(QtWidgets.QTabWidget, self.results)
        if mode in (setools.DomainTransitionAnalysis.Mode.TransitionsIn,
                    setools.DomainTransitionAnalysis.Mode.TransitionsOut):
            results.setTabEnabled(tab.DirectedGraphResultTab.ResultTab.Tree, True)
            self.worker.render = DomainTransitionAnalysisTab.render_direct_path
        else:
            results.setTabEnabled(tab.DirectedGraphResultTab.ResultTab.Tree, False)
            self.worker.render = DomainTransitionAnalysisTab.render_transitive_path

    def _apply_result_limit(self, value: int = DEFAULT_RESULT_LIMIT) -> None:
        """Apply result limit change."""
        assert isinstance(self.query, setools.DomainTransitionAnalysis)  # type narrowing
        self.log.debug(f"Setting result limit to {value} flows.")
        self.worker.result_limit = value

    def _show_help(self) -> None:
        """Show help dialog."""
        HtmlHelpDialog.from_package_file("Domain Transition Analysis Help",
                                         HELP_PAGE,
                                         parent=self).open()

    @staticmethod
    def render_direct_path(count: int, step: setools.DomainTransition) -> str:
        """Render text representation of domain transition in/out results."""
        return f"Transition {count}: {step:full}\n"

    @staticmethod
    def render_transitive_path(count: int, path: setools.DTAPath) -> str:
        """Render text representation of all/shortest paths results."""
        lines = [f"Transition {count}:"]
        for stepnum, step in enumerate(path, start=1):
            lines.append(f"  Step {stepnum}: {step:full}\n")
        return "\n".join(lines)


class DTAMode(criteria.RadioEnumWidget[setools.DomainTransitionAnalysis.Mode]):

    """Domain transition analysis mode radio buttons."""

    def __init__(self, query: setools.DomainTransitionAnalysis,
                 parent: QtWidgets.QWidget | None = None) -> None:

        # colspan 2 so the below spinbox fits better with the radio button.
        super().__init__("Analysis Mode", query, SETTINGS_MODE,
                         setools.DomainTransitionAnalysis.Mode, colspan=2, parent=parent)

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
            self.criteria[setools.DomainTransitionAnalysis.Mode.AllPaths])
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
        self.criteria[setools.DomainTransitionAnalysis.Mode.AllPaths].toggled.connect(
            self._apply_depth_limit_from_mode_change)

    def _apply_depth_limit(self, value: int = DEFAULT_DEPTH_LIMIT) -> None:
        """Apply the value of the all paths spinbox to the query."""
        assert isinstance(self.query, setools.DomainTransitionAnalysis)  # type narrowing
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


class DTAOptions(criteria.CriteriaWidget):

    """
    Domain transition analysis options widget.

    Presents the options:
    * Reverse
    * Limit number of results
    * Exclude types button
    """

    has_errors: typing.Final[bool] = False
    result_limit_changed = QtCore.pyqtSignal(int)

    def __init__(self, query: setools.DomainTransitionAnalysis,
                 parent: QtWidgets.QWidget | None = None) -> None:

        super().__init__("Options", query, "", parent=parent)

        self.top_layout = QtWidgets.QFormLayout(self)
        self.top_layout.setLabelAlignment(QtCore.Qt.AlignmentFlag.AlignRight)

        self.reverse = QtWidgets.QCheckBox(self)
        self.reverse.stateChanged.connect(self._apply_reverse)
        self.reverse.setTristate(False)
        self.reverse.setChecked(DEFAULT_REVERSE)
        self.top_layout.addRow(QtWidgets.QLabel("Reverse:", self),
                               self.reverse)

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

    def _apply_reverse(self, state: int) -> None:
        """Set the reverse boolean value."""
        assert isinstance(self.query, setools.DomainTransitionAnalysis)  # type narrowing
        self.log.debug(f"Setting reverse {state}")
        self.query.reverse = bool(state)

    def _start_type_exclude(self) -> None:
        ExcludeTypes(self.query, parent=self).open()

    def save(self, settings: dict) -> None:
        assert isinstance(self.query, setools.DomainTransitionAnalysis)  # type narrowing
        super().save(settings)
        settings[SETTINGS_RESULT_LIMIT] = self.result_limit.value()
        settings[SETTINGS_EXCLUDE_TYPES] = [str(t) for t in self.query.exclude]
        settings[SETTINGS_REVERSE] = self.reverse.isChecked()

    def load(self, settings: dict) -> None:
        assert isinstance(self.query, setools.DomainTransitionAnalysis)  # type narrowing
        with suppress(KeyError):
            self.reverse.setChecked(settings[SETTINGS_REVERSE])

        with suppress(KeyError):
            self.result_limit.setValue(settings[SETTINGS_RESULT_LIMIT])

        with suppress(KeyError):
            self.query.exclude = settings[SETTINGS_EXCLUDE_TYPES]

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
    widget = DomainTransitionAnalysisTab(setools.SELinuxPolicy(), parent=mw)
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
