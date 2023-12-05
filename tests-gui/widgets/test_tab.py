# SPDX-License-Identifier: GPL-2.0-only
from typing import cast

from PyQt6 import QtWidgets
import pytest
from pytestqt.qtbot import QtBot

from setoolsgui.widgets import tab


@pytest.fixture
def base_widget(mock_policy, request: pytest.FixtureRequest,
                qtbot: QtBot) -> tab.BaseAnalysisTabWidget:
    """Pytest fixture to set up the BaseAnalysisTabWidget widget."""
    marker = request.node.get_closest_marker("obj_args")
    kwargs = marker.kwargs if marker else {}
    w = tab.BaseAnalysisTabWidget(mock_policy, **kwargs)
    qtbot.addWidget(w)
    w.show()
    return w


@pytest.fixture
def table_widget(mock_policy, request: pytest.FixtureRequest,
                 qtbot: QtBot) -> tab.TableResultTabWidget:
    """Pytest fixture to set up the TableResultTabWidget widget."""
    marker = request.node.get_closest_marker("obj_args")
    kwargs = marker.kwargs if marker else {}
    w = tab.TableResultTabWidget(mock_policy, **kwargs)
    qtbot.addWidget(w)
    w.show()
    return w


@pytest.mark.obj_args(enable_criteria=True)
def test_basetab_layout(base_widget: tab.BaseAnalysisTabWidget) -> None:
    """Test BaseAnalysisTabWidget with criteria."""
    assert base_widget.analysis_layout.columnCount() == 5
    assert base_widget.analysis_layout.rowCount() == 4
    assert base_widget.analysis_layout.itemAtPosition(0, 3).widget() == \
        base_widget.criteria_expander
    assert base_widget.analysis_layout.itemAtPosition(0, 4).widget() == base_widget.notes_expander
    assert base_widget.analysis_layout.itemAtPosition(1, 0).widget() == base_widget.criteria_frame
    assert not base_widget.analysis_layout.itemAtPosition(2, 0)  # result widget set by subclasses
    assert base_widget.analysis_layout.itemAtPosition(3, 0).widget() == base_widget.notes


@pytest.mark.obj_args(enable_criteria=False)
def test_basetab_layout_nocriteria(base_widget: tab.BaseAnalysisTabWidget) -> None:
    """Test BaseAnalysisTabWidget without criteria."""
    assert base_widget.analysis_layout.columnCount() == 5
    assert base_widget.analysis_layout.rowCount() == 4
    assert not base_widget.analysis_layout.itemAtPosition(0, 3)  # no criteria expander
    assert base_widget.analysis_layout.itemAtPosition(0, 4).widget() == base_widget.notes_expander
    assert not base_widget.analysis_layout.itemAtPosition(1, 0)  # no criteria pane
    assert not base_widget.analysis_layout.itemAtPosition(2, 0)  # result widget set by subclasses
    assert base_widget.analysis_layout.itemAtPosition(3, 0).widget() == base_widget.notes


@pytest.mark.obj_args(enable_criteria=True)
def test_basetab_criteria_expander(base_widget: tab.BaseAnalysisTabWidget) -> None:
    """Test BaseAnalysisTabWidget criteria expander behavior."""
    if tab.CRITERIA_DEFAULT_CHECKED:
        assert base_widget.criteria_frame.isVisible()
        base_widget.criteria_expander.click()
        assert not base_widget.criteria_frame.isVisible()
        base_widget.criteria_expander.click()
        assert base_widget.criteria_frame.isVisible()
    else:
        assert not base_widget.criteria_frame.isVisible()
        base_widget.criteria_expander.click()
        assert base_widget.criteria_frame.isVisible()
        base_widget.criteria_expander.click()
        assert not base_widget.criteria_frame.isVisible()


@pytest.mark.obj_args(enable_criteria=True)
def test_basetab_notes_expander(base_widget: tab.BaseAnalysisTabWidget) -> None:
    """Test BaseAnalysisTabWidget notes expander behavior."""
    if tab.NOTES_DEFAULT_CHECKED:
        assert base_widget.notes.isVisible()
        base_widget.notes_expander.click()
        assert not base_widget.notes.isVisible()
        base_widget.notes_expander.click()
        assert base_widget.notes.isVisible()
    else:
        assert not base_widget.notes.isVisible()
        base_widget.notes_expander.click()
        assert base_widget.notes.isVisible()
        base_widget.notes_expander.click()
        assert not base_widget.notes.isVisible()


@pytest.mark.obj_args(enable_criteria=True)
def test_tableresulttab_layout(table_widget: tab.TableResultTabWidget) -> None:
    """Test TableResultTabWidget layout."""
    results_widget = cast(QtWidgets.QTabWidget, table_widget.results)
    assert table_widget.analysis_layout.columnCount() == 5
    assert table_widget.analysis_layout.rowCount() == 4
    assert table_widget.analysis_layout.itemAtPosition(0, 3).widget() == \
        table_widget.criteria_expander
    assert table_widget.analysis_layout.itemAtPosition(0, 4).widget() == \
        table_widget.notes_expander
    assert table_widget.analysis_layout.itemAtPosition(1, 0).widget() == \
        table_widget.criteria_frame
    assert table_widget.analysis_layout.itemAtPosition(2, 0).widget() == results_widget
    assert table_widget.analysis_layout.itemAtPosition(3, 0).widget() == table_widget.notes

    assert results_widget.count() == 2
    assert results_widget.widget(0) == table_widget.table_results
    assert results_widget.widget(1) == table_widget.raw_results
