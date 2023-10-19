# SPDX-License-Identifier: GPL-2.0-only
from typing import Dict, List, Final

from pytestqt.qtbot import QtBot

from setoolsgui.widgets.criteria.checkboxset import CheckboxSetCriteriaWidget

from .util import build_mock_query

CHECKBOXES = ("cb1", "cb2", "cb3")


def test_base_settings(qtbot: QtBot) -> None:
    """Test base properties of widget."""
    mock_query = build_mock_query()
    widget = CheckboxSetCriteriaWidget("title", mock_query, "checkboxes", CHECKBOXES)
    qtbot.addWidget(widget)

    assert widget.attrname == "checkboxes"
    assert len(widget.criteria) == len(CHECKBOXES)


def test_3across_layout(qtbot: QtBot) -> None:
    """Test three checkboxes all in one row layout."""
    mock_query = build_mock_query()
    widget = CheckboxSetCriteriaWidget("title", mock_query, "checkboxes", CHECKBOXES,
                                       num_cols=3)
    qtbot.addWidget(widget)

    # validate widget item positions
    assert widget.top_layout.itemAtPosition(0, 0).widget() == widget.criteria["cb1"]
    assert widget.top_layout.itemAtPosition(0, 1).widget() == widget.criteria["cb2"]
    assert widget.top_layout.itemAtPosition(0, 2).widget() == widget.criteria["cb3"]
    assert widget.top_layout.itemAtPosition(0, 3).widget() == widget.clear_criteria
    assert not widget.top_layout.itemAtPosition(1, 0)
    assert not widget.top_layout.itemAtPosition(1, 1)
    assert not widget.top_layout.itemAtPosition(1, 2)
    assert widget.top_layout.itemAtPosition(1, 3).widget() == widget.invert_criteria


def test_2across_layout(qtbot: QtBot) -> None:
    """Test two columns of checkboxes layout."""
    mock_query = build_mock_query()
    widget = CheckboxSetCriteriaWidget("title", mock_query, "checkboxes", CHECKBOXES,
                                       num_cols=2)
    qtbot.addWidget(widget)

    # validate widget item positions
    assert widget.top_layout.itemAtPosition(0, 0).widget() == widget.criteria["cb1"]
    assert widget.top_layout.itemAtPosition(0, 1).widget() == widget.criteria["cb2"]
    assert widget.top_layout.itemAtPosition(0, 2).widget() == widget.clear_criteria
    assert widget.top_layout.itemAtPosition(1, 0).widget() == widget.criteria["cb3"]
    assert not widget.top_layout.itemAtPosition(1, 1)
    assert widget.top_layout.itemAtPosition(1, 2).widget() == widget.invert_criteria


def test_1across_layout(qtbot: QtBot) -> None:
    """Test one column of checkboxes layout."""
    mock_query = build_mock_query()
    widget = CheckboxSetCriteriaWidget("title", mock_query, "checkboxes", CHECKBOXES,
                                       num_cols=1)
    qtbot.addWidget(widget)

    # validate widget item positions
    assert widget.top_layout.itemAtPosition(0, 0).widget() == widget.criteria["cb1"]
    assert widget.top_layout.itemAtPosition(0, 1).widget() == widget.clear_criteria
    assert widget.top_layout.itemAtPosition(1, 0).widget() == widget.criteria["cb2"]
    assert widget.top_layout.itemAtPosition(1, 1).widget() == widget.invert_criteria
    assert widget.top_layout.itemAtPosition(2, 0).widget() == widget.criteria["cb3"]
    assert not widget.top_layout.itemAtPosition(2, 1)


def test_selection(qtbot: QtBot) -> None:
    """Test checked boxes are reflected in the query."""
    mock_query = build_mock_query()
    widget = CheckboxSetCriteriaWidget("title", mock_query, "checkboxes", CHECKBOXES,
                                       num_cols=1)
    qtbot.addWidget(widget)

    assert not widget.criteria["cb1"].isChecked()
    assert not widget.criteria["cb2"].isChecked()
    assert not widget.criteria["cb3"].isChecked()

    widget.criteria["cb1"].setChecked(True)
    widget.criteria["cb2"].setChecked(False)
    widget.criteria["cb3"].setChecked(True)

    assert widget.selection() == ["cb1", "cb3"]
    assert mock_query.checkboxes == ["cb1", "cb3"]


def test_set_selection(qtbot: QtBot) -> None:
    """Test set_selection method."""
    mock_query = build_mock_query()
    widget = CheckboxSetCriteriaWidget("title", mock_query, "checkboxes", CHECKBOXES,
                                       num_cols=1)
    qtbot.addWidget(widget)

    # This to verify the current selection is cleared.
    widget.criteria["cb1"].setChecked(True)

    widget.set_selection(["cb2", "cb3"])

    assert not widget.criteria["cb1"].isChecked()
    assert widget.criteria["cb2"].isChecked()
    assert widget.criteria["cb3"].isChecked()
    assert widget.selection() == ["cb2", "cb3"]
    assert mock_query.checkboxes == ["cb2", "cb3"]


def test_clear_selection(qtbot: QtBot) -> None:
    """Test clear selection button."""
    mock_query = build_mock_query()
    widget = CheckboxSetCriteriaWidget("title", mock_query, "checkboxes", CHECKBOXES,
                                       num_cols=1)
    qtbot.addWidget(widget)

    widget.set_selection(["cb1", "cb2"])
    widget.clear_criteria.click()

    assert not widget.criteria["cb1"].isChecked()
    assert not widget.criteria["cb2"].isChecked()
    assert not widget.criteria["cb3"].isChecked()
    assert widget.selection() == []
    assert mock_query.checkboxes == []


def test_invert_selection(qtbot: QtBot) -> None:
    """Test clear selection button."""
    mock_query = build_mock_query()
    widget = CheckboxSetCriteriaWidget("title", mock_query, "checkboxes", CHECKBOXES,
                                       num_cols=1)
    qtbot.addWidget(widget)

    widget.set_selection(["cb1", "cb2"])
    widget.invert_criteria.click()

    assert not widget.criteria["cb1"].isChecked()
    assert not widget.criteria["cb2"].isChecked()
    assert widget.criteria["cb3"].isChecked()
    assert widget.selection() == ["cb3"]
    assert mock_query.checkboxes == ["cb3"]


def test_save(qtbot: QtBot) -> None:
    """Test save."""
    mock_query = build_mock_query()
    widget = CheckboxSetCriteriaWidget("title", mock_query, "checkboxes", CHECKBOXES,
                                       num_cols=1)
    qtbot.addWidget(widget)

    selection = ["cb2", "cb3"]
    expected: Final = {"checkboxes": selection}

    widget.set_selection(selection)

    settings: Dict[str, List[str]] = {}
    widget.save(settings)

    assert expected == settings


def test_load(qtbot: QtBot) -> None:
    """Test load."""
    mock_query = build_mock_query()
    widget = CheckboxSetCriteriaWidget("title", mock_query, "checkboxes", CHECKBOXES,
                                       num_cols=1)
    qtbot.addWidget(widget)

    selection = ["cb1", "cb3"]
    settings: Final = {"checkboxes": selection}

    widget.load(settings)

    assert widget.selection() == selection


def test_set_selection_disabled(qtbot: QtBot) -> None:
    """Test set_selection method, ignoring disabled boxes."""
    mock_query = build_mock_query()
    widget = CheckboxSetCriteriaWidget("title", mock_query, "checkboxes", CHECKBOXES,
                                       num_cols=1)
    qtbot.addWidget(widget)

    widget.criteria["cb2"].setDisabled(True)

    widget.set_selection(["cb2", "cb3"])

    assert not widget.criteria["cb1"].isChecked()
    assert not widget.criteria["cb2"].isChecked()
    assert widget.criteria["cb3"].isChecked()
    assert widget.selection() == ["cb3"]
    assert mock_query.checkboxes == ["cb3"]


def test_clear_selection_disabled(qtbot: QtBot) -> None:
    """Test clear selection button, ignoring disabled boxes."""
    mock_query = build_mock_query()
    widget = CheckboxSetCriteriaWidget("title", mock_query, "checkboxes", CHECKBOXES,
                                       num_cols=1)
    qtbot.addWidget(widget)

    widget.set_selection(["cb1", "cb2"])
    widget.criteria["cb2"].setDisabled(True)

    widget.clear_criteria.click()

    assert not widget.criteria["cb1"].isChecked()
    assert widget.criteria["cb2"].isChecked()
    assert not widget.criteria["cb3"].isChecked()
    assert widget.selection() == ["cb2"]
    assert mock_query.checkboxes == ["cb2"]


def test_invert_selection_disabled(qtbot: QtBot) -> None:
    """Test clear selection button, ignoring disabled boxes."""
    mock_query = build_mock_query()
    widget = CheckboxSetCriteriaWidget("title", mock_query, "checkboxes", CHECKBOXES,
                                       num_cols=1)
    qtbot.addWidget(widget)

    widget.set_selection(["cb1", "cb2"])
    widget.criteria["cb2"].setDisabled(True)

    widget.invert_criteria.click()

    assert not widget.criteria["cb1"].isChecked()
    assert widget.criteria["cb2"].isChecked()
    assert widget.criteria["cb3"].isChecked()
    assert widget.selection() == ["cb2", "cb3"]
    assert mock_query.checkboxes == ["cb2", "cb3"]
