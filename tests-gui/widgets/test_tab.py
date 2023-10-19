# SPDX-License-Identifier: GPL-2.0-only
from typing import cast

from PyQt5 import QtCore, QtWidgets
from pytestqt.qtbot import QtBot

from setoolsgui.widgets import tab

from .criteria.util import build_mock_query


def test_basetab_layout(qtbot: QtBot) -> None:
    """Test BaseAnalysisTabWidget with criteria."""
    widget = tab.BaseAnalysisTabWidget(enable_criteria=True)
    qtbot.addWidget(widget)

    assert widget.top_layout.columnCount() == 5
    assert widget.top_layout.rowCount() == 4
    assert widget.top_layout.itemAtPosition(0, 3).widget() == widget.criteria_expander
    assert widget.top_layout.itemAtPosition(0, 4).widget() == widget.notes_expander
    assert widget.top_layout.itemAtPosition(1, 0).widget() == widget.criteria_frame
    assert not widget.top_layout.itemAtPosition(2, 0)  # result widget set by subclasses
    assert widget.top_layout.itemAtPosition(3, 0).widget() == widget.notes


def test_basetab_layout_nocriteria(qtbot: QtBot) -> None:
    """Test BaseAnalysisTabWidget without criteria."""
    widget = tab.BaseAnalysisTabWidget(enable_criteria=False)
    qtbot.addWidget(widget)

    assert widget.top_layout.columnCount() == 5
    assert widget.top_layout.rowCount() == 4
    assert not widget.top_layout.itemAtPosition(0, 3)  # no criteria expander
    assert widget.top_layout.itemAtPosition(0, 4).widget() == widget.notes_expander
    assert not widget.top_layout.itemAtPosition(1, 0)  # no criteria pane
    assert not widget.top_layout.itemAtPosition(2, 0)  # result widget set by subclasses
    assert widget.top_layout.itemAtPosition(3, 0).widget() == widget.notes


def test_basetab_criteria_expander(qtbot: QtBot) -> None:
    """Test BaseAnalysisTabWidget criteria expander behavior."""
    widget = tab.BaseAnalysisTabWidget(enable_criteria=True)
    qtbot.addWidget(widget)
    widget.show()

    if tab.CRITERIA_DEFAULT_CHECKED:
        assert widget.criteria_frame.isVisible()
        qtbot.mouseClick(widget.criteria_expander, QtCore.Qt.MouseButton.LeftButton)
        assert not widget.criteria_frame.isVisible()
        qtbot.mouseClick(widget.criteria_expander, QtCore.Qt.MouseButton.LeftButton)
        assert widget.criteria_frame.isVisible()
    else:
        assert not widget.criteria_frame.isVisible()
        qtbot.mouseClick(widget.criteria_expander, QtCore.Qt.MouseButton.LeftButton)
        assert widget.criteria_frame.isVisible()
        qtbot.mouseClick(widget.criteria_expander, QtCore.Qt.MouseButton.LeftButton)
        assert not widget.criteria_frame.isVisible()


def test_basetab_notes_expander(qtbot: QtBot) -> None:
    """Test BaseAnalysisTabWidget notes expander behavior."""
    widget = tab.BaseAnalysisTabWidget(enable_criteria=True)
    qtbot.addWidget(widget)
    widget.show()

    if tab.NOTES_DEFAULT_CHECKED:
        assert widget.notes.isVisible()
        qtbot.mouseClick(widget.notes_expander, QtCore.Qt.MouseButton.LeftButton)
        assert not widget.notes.isVisible()
        qtbot.mouseClick(widget.notes_expander, QtCore.Qt.MouseButton.LeftButton)
        assert widget.notes.isVisible()
    else:
        assert not widget.notes.isVisible()
        qtbot.mouseClick(widget.notes_expander, QtCore.Qt.MouseButton.LeftButton)
        assert widget.notes.isVisible()
        qtbot.mouseClick(widget.notes_expander, QtCore.Qt.MouseButton.LeftButton)
        assert not widget.notes.isVisible()


def test_tableresulttab_layout(qtbot: QtBot) -> None:
    """Test TableResultTabWidget layout."""
    mock_query = build_mock_query()
    widget = tab.TableResultTabWidget(mock_query, enable_criteria=True)
    qtbot.addWidget(widget)

    results_widget = cast(QtWidgets.QTabWidget, widget.results)
    assert widget.top_layout.columnCount() == 5
    assert widget.top_layout.rowCount() == 4
    assert widget.top_layout.itemAtPosition(0, 3).widget() == widget.criteria_expander
    assert widget.top_layout.itemAtPosition(0, 4).widget() == widget.notes_expander
    assert widget.top_layout.itemAtPosition(1, 0).widget() == widget.criteria_frame
    assert widget.top_layout.itemAtPosition(2, 0).widget() == results_widget
    assert widget.top_layout.itemAtPosition(3, 0).widget() == widget.notes

    assert results_widget.count() == 2
    assert results_widget.widget(0) == widget.table_results
    assert results_widget.widget(1) == widget.raw_results
