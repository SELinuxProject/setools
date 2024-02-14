# SPDX-License-Identifier: GPL-2.0-only
from typing import Dict, List, Final

import pytest
from pytestqt.qtbot import QtBot

from setoolsgui.widgets.criteria.checkboxset import CheckboxSetWidget

CHECKBOXES = ("cb1", "cb2", "cb3")


@pytest.fixture
def widget(mock_query, request: pytest.FixtureRequest, qtbot: QtBot) -> CheckboxSetWidget:
    """Pytest fixture to set up the widget."""
    marker = request.node.get_closest_marker("obj_args")
    kwargs = marker.kwargs if marker else {}
    w = CheckboxSetWidget(request.node.name, mock_query, "checkboxes", CHECKBOXES, **kwargs)
    qtbot.addWidget(w)
    w.show()
    return w


def test_base_settings(widget: CheckboxSetWidget) -> None:
    """Test base properties of CheckboxSetCriteriaWidget."""
    assert widget.attrname == "checkboxes"
    assert len(widget.criteria) == len(CHECKBOXES)


@pytest.mark.obj_args(num_cols=3)
def test_3across_layout(widget: CheckboxSetWidget) -> None:
    """Test three checkboxes all in one row layout."""
    # validate widget item positions
    assert widget.top_layout.itemAtPosition(0, 0).widget() == widget.criteria["cb1"]
    assert widget.top_layout.itemAtPosition(0, 1).widget() == widget.criteria["cb2"]
    assert widget.top_layout.itemAtPosition(0, 2).widget() == widget.criteria["cb3"]
    assert widget.top_layout.itemAtPosition(0, 3).widget() == widget.clear_criteria
    assert not widget.top_layout.itemAtPosition(1, 0)
    assert not widget.top_layout.itemAtPosition(1, 1)
    assert not widget.top_layout.itemAtPosition(1, 2)
    assert widget.top_layout.itemAtPosition(1, 3).widget() == widget.invert_criteria


@pytest.mark.obj_args(num_cols=2)
def test_2across_layout(widget: CheckboxSetWidget) -> None:
    """Test two columns of checkboxes layout."""
    # validate widget item positions
    assert widget.top_layout.itemAtPosition(0, 0).widget() == widget.criteria["cb1"]
    assert widget.top_layout.itemAtPosition(0, 1).widget() == widget.criteria["cb2"]
    assert widget.top_layout.itemAtPosition(0, 2).widget() == widget.clear_criteria
    assert widget.top_layout.itemAtPosition(1, 0).widget() == widget.criteria["cb3"]
    assert not widget.top_layout.itemAtPosition(1, 1)
    assert widget.top_layout.itemAtPosition(1, 2).widget() == widget.invert_criteria


@pytest.mark.obj_args(num_cols=1)
def test_1across_layout(widget: CheckboxSetWidget) -> None:
    """Test one column of checkboxes layout."""
    # validate widget item positions
    assert widget.top_layout.itemAtPosition(0, 0).widget() == widget.criteria["cb1"]
    assert widget.top_layout.itemAtPosition(0, 1).widget() == widget.clear_criteria
    assert widget.top_layout.itemAtPosition(1, 0).widget() == widget.criteria["cb2"]
    assert widget.top_layout.itemAtPosition(1, 1).widget() == widget.invert_criteria
    assert widget.top_layout.itemAtPosition(2, 0).widget() == widget.criteria["cb3"]
    assert not widget.top_layout.itemAtPosition(2, 1)


def test_selection(widget: CheckboxSetWidget, mock_query) -> None:
    """Test checked boxes are reflected in the query."""
    assert not widget.criteria["cb1"].isChecked()
    assert not widget.criteria["cb2"].isChecked()
    assert not widget.criteria["cb3"].isChecked()

    widget.criteria["cb1"].setChecked(True)
    widget.criteria["cb2"].setChecked(False)
    widget.criteria["cb3"].setChecked(True)

    assert widget.selection() == ["cb1", "cb3"]
    assert mock_query.checkboxes == ["cb1", "cb3"]


def test_set_selection(widget: CheckboxSetWidget, mock_query) -> None:
    """Test set_selection method."""
    # This to verify the current selection is cleared.
    widget.criteria["cb1"].setChecked(True)

    widget.set_selection(["cb2", "cb3"])

    assert not widget.criteria["cb1"].isChecked()
    assert widget.criteria["cb2"].isChecked()
    assert widget.criteria["cb3"].isChecked()
    assert widget.selection() == ["cb2", "cb3"]
    assert mock_query.checkboxes == ["cb2", "cb3"]


def test_clear_selection(widget: CheckboxSetWidget, mock_query) -> None:
    """Test clear selection button."""
    widget.set_selection(["cb1", "cb2"])
    widget.clear_criteria.click()

    assert not widget.criteria["cb1"].isChecked()
    assert not widget.criteria["cb2"].isChecked()
    assert not widget.criteria["cb3"].isChecked()
    assert widget.selection() == []
    assert mock_query.checkboxes == []


def test_invert_selection(widget: CheckboxSetWidget, mock_query) -> None:
    """Test clear selection button."""
    widget.set_selection(["cb1", "cb2"])
    widget.invert_criteria.click()

    assert not widget.criteria["cb1"].isChecked()
    assert not widget.criteria["cb2"].isChecked()
    assert widget.criteria["cb3"].isChecked()
    assert widget.selection() == ["cb3"]
    assert mock_query.checkboxes == ["cb3"]


def test_save(widget: CheckboxSetWidget) -> None:
    """Test save."""
    selection = ["cb2", "cb3"]
    expected: Final = {"checkboxes": selection}

    widget.set_selection(selection)

    settings: Dict[str, List[str]] = {}
    widget.save(settings)

    assert expected == settings


def test_load(widget: CheckboxSetWidget) -> None:
    """Test load."""
    selection = ["cb1", "cb3"]
    settings: Final = {"checkboxes": selection}

    widget.load(settings)

    assert widget.selection() == selection


def test_set_selection_disabled(widget: CheckboxSetWidget, mock_query) -> None:
    """Test set_selection method, ignoring disabled boxes."""
    widget.criteria["cb2"].setDisabled(True)

    widget.set_selection(["cb2", "cb3"])

    assert not widget.criteria["cb1"].isChecked()
    assert not widget.criteria["cb2"].isChecked()
    assert widget.criteria["cb3"].isChecked()
    assert widget.selection() == ["cb3"]
    assert mock_query.checkboxes == ["cb3"]


def test_clear_selection_disabled(widget: CheckboxSetWidget, mock_query) -> None:
    """Test clear selection button, ignoring disabled boxes."""
    widget.set_selection(["cb1", "cb2"])
    widget.criteria["cb2"].setDisabled(True)

    widget.clear_criteria.click()

    assert not widget.criteria["cb1"].isChecked()
    assert widget.criteria["cb2"].isChecked()
    assert not widget.criteria["cb3"].isChecked()
    assert widget.selection() == ["cb2"]
    assert mock_query.checkboxes == ["cb2"]


def test_invert_selection_disabled(widget: CheckboxSetWidget, mock_query) -> None:
    """Test clear selection button, ignoring disabled boxes."""
    widget.set_selection(["cb1", "cb2"])
    widget.criteria["cb2"].setDisabled(True)

    widget.invert_criteria.click()

    assert not widget.criteria["cb1"].isChecked()
    assert widget.criteria["cb2"].isChecked()
    assert widget.criteria["cb3"].isChecked()
    assert widget.selection() == ["cb2", "cb3"]
    assert mock_query.checkboxes == ["cb2", "cb3"]
