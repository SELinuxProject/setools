# SPDX-License-Identifier: GPL-2.0-only
from typing import Dict, Final, List, Union

from PyQt5 import QtCore, QtWidgets
from pytestqt.qtbot import QtBot

from setoolsgui.widgets.criteria.list import (EQUAL_DEFAULT_CHECKED, ListCriteriaWidget,
                                              SUBSET_DEFAULT_CHECKED)
from setoolsgui.widgets.models.table import StringList

from . import util


def _setup_widget(testname: str, **kwargs) -> tuple[ListCriteriaWidget, StringList]:
    """Set up widget for testing."""
    model = StringList(data=["item1", "item2", "item3"])
    widget = ListCriteriaWidget(testname, util.build_mock_query(), "name", model, **kwargs)
    model.setParent(widget)
    return widget, model


def test_base_settings(qtbot: QtBot) -> None:
    """Test base properties of widget."""
    widget, _ = _setup_widget("test_base_settings", enable_equal=True, enable_subset=True)
    qtbot.addWidget(widget)

    assert widget.clear_criteria.toolTip()
    assert widget.clear_criteria.whatsThis()
    assert widget.invert_criteria.toolTip()
    assert widget.invert_criteria.whatsThis()
    assert widget.criteria.objectName() == "name"
    assert widget.criteria.selectionMode() == \
        QtWidgets.QAbstractItemView.SelectionMode.ExtendedSelection
    assert widget.criteria_equal.objectName() == "name_equal"
    assert widget.criteria_subset.objectName() == "name_subset"


def test_equal_subset_disabled_layout(qtbot: QtBot) -> None:
    """Test layout for no equal and subset options."""
    widget, _ = _setup_widget("test_equal_subset_disabled_layout", enable_equal=False,
                              enable_subset=False)
    qtbot.addWidget(widget)

    # validate widget item positions
    assert widget.top_layout.itemAtPosition(0, 0).widget() == widget.criteria
    assert widget.top_layout.itemAtPosition(0, 1).widget() == widget.clear_criteria
    assert widget.top_layout.itemAtPosition(0, 2).widget() == widget.criteria_any
    assert widget.top_layout.itemAtPosition(1, 0).widget() == widget.criteria
    assert widget.top_layout.itemAtPosition(1, 1).widget() == widget.invert_criteria
    assert not widget.top_layout.itemAtPosition(1, 2)
    assert widget.top_layout.itemAtPosition(2, 0).widget() == widget.criteria
    assert not widget.top_layout.itemAtPosition(2, 1)
    assert not widget.top_layout.itemAtPosition(2, 2)


def test_equal_enabled_subset_disabled_layout(qtbot: QtBot) -> None:
    """Test layout for equal enabled and subset disabled options."""
    widget, _ = _setup_widget("test_equal_enabled_subset_disabled_layout", enable_equal=True,
                              enable_subset=False)
    qtbot.addWidget(widget)

    # validate widget item positions
    assert widget.top_layout.itemAtPosition(0, 0).widget() == widget.criteria
    assert widget.top_layout.itemAtPosition(0, 1).widget() == widget.clear_criteria
    assert widget.top_layout.itemAtPosition(0, 2).widget() == widget.criteria_any
    assert widget.top_layout.itemAtPosition(1, 0).widget() == widget.criteria
    assert widget.top_layout.itemAtPosition(1, 1).widget() == widget.invert_criteria
    assert widget.top_layout.itemAtPosition(1, 2).widget() == widget.criteria_equal
    assert widget.top_layout.itemAtPosition(2, 0).widget() == widget.criteria
    assert not widget.top_layout.itemAtPosition(2, 1)
    assert not widget.top_layout.itemAtPosition(2, 2)


def test_equal_disabled_subset_enabled_layout(qtbot: QtBot) -> None:
    """Test layout for equal disabled and subset enabled options."""
    widget, _ = _setup_widget("test_equal_disabled_subset_enabled_layout", enable_equal=False,
                              enable_subset=True)
    qtbot.addWidget(widget)

    # validate widget item positions
    assert widget.top_layout.itemAtPosition(0, 0).widget() == widget.criteria
    assert widget.top_layout.itemAtPosition(0, 1).widget() == widget.clear_criteria
    assert widget.top_layout.itemAtPosition(0, 2).widget() == widget.criteria_any
    assert widget.top_layout.itemAtPosition(1, 0).widget() == widget.criteria
    assert widget.top_layout.itemAtPosition(1, 1).widget() == widget.invert_criteria
    assert not widget.top_layout.itemAtPosition(1, 2)
    assert widget.top_layout.itemAtPosition(2, 0).widget() == widget.criteria
    assert not widget.top_layout.itemAtPosition(2, 1)
    assert widget.top_layout.itemAtPosition(2, 2).widget() == widget.criteria_subset


def test_equal_subset_enabled_layout(qtbot: QtBot) -> None:
    """Test layout for equal and subset enabled options."""
    widget, _ = _setup_widget("test_equal_subset_enabled_layout", enable_equal=True,
                              enable_subset=True)
    qtbot.addWidget(widget)

    # validate widget item positions
    assert widget.top_layout.itemAtPosition(0, 0).widget() == widget.criteria
    assert widget.top_layout.itemAtPosition(0, 1).widget() == widget.clear_criteria
    assert widget.top_layout.itemAtPosition(0, 2).widget() == widget.criteria_any
    assert widget.top_layout.itemAtPosition(1, 0).widget() == widget.criteria
    assert widget.top_layout.itemAtPosition(1, 1).widget() == widget.invert_criteria
    assert widget.top_layout.itemAtPosition(1, 2).widget() == widget.criteria_equal
    assert widget.top_layout.itemAtPosition(2, 0).widget() == widget.criteria
    assert not widget.top_layout.itemAtPosition(2, 1)
    assert widget.top_layout.itemAtPosition(2, 2).widget() == widget.criteria_subset


def test_set_selection(qtbot: QtBot) -> None:
    """Test setting a selection."""
    widget, model = _setup_widget("test_set_selection")
    qtbot.addWidget(widget)

    test_selection = [model.item_list[0], model.item_list[2]]
    widget.criteria.set_selection(test_selection)
    assert list(widget.criteria.selection()) == test_selection
    assert widget.query.name == test_selection
    assert not widget.has_errors


def test_invert_selection(qtbot: QtBot) -> None:
    """Test inverting a selection."""
    widget, model = _setup_widget("test_invert_selection")
    qtbot.addWidget(widget)

    inverted_selection = [model.item_list[1]]
    widget.criteria.set_selection([model.item_list[0], model.item_list[2]])
    qtbot.mouseClick(widget.invert_criteria, QtCore.Qt.MouseButton.LeftButton)
    assert list(widget.criteria.selection()) == inverted_selection
    assert widget.query.name == inverted_selection
    assert not widget.has_errors


def test_clear_selection(qtbot: QtBot) -> None:
    """Test clearing a selection."""
    widget, model = _setup_widget("test_clear_selection")
    qtbot.addWidget(widget)

    widget.criteria.set_selection([model.item_list[0], model.item_list[2]])
    assert list(widget.criteria.selection())
    qtbot.mouseClick(widget.clear_criteria, QtCore.Qt.MouseButton.LeftButton)
    assert not list(widget.criteria.selection())
    assert not widget.query.name
    assert not widget.has_errors


def test_equal_toggling(qtbot: QtBot) -> None:
    """Test equal match toggling is reflected in the query."""
    widget, _ = _setup_widget("test_equal_toggling", enable_equal=True, enable_subset=False)
    qtbot.addWidget(widget)

    # test radio button toggling based on the initial state
    if EQUAL_DEFAULT_CHECKED:
        widget.criteria_any.setChecked(True)
        assert widget.query.name_equal is False
        widget.criteria_equal.setChecked(True)
        assert widget.query.name_equal is True
    else:
        widget.criteria_equal.setChecked(True)
        assert widget.query.name_equal is True
        widget.criteria_any.setChecked(True)
        assert widget.query.name_equal is False


def test_subset_toggling(qtbot: QtBot) -> None:
    """Test subset match toggling is reflected in the query."""
    widget, _ = _setup_widget("test_subset_toggling", enable_equal=False, enable_subset=True)
    qtbot.addWidget(widget)

    # test radio button toggling based on the initial state
    if SUBSET_DEFAULT_CHECKED:
        widget.criteria_any.setChecked(True)
        assert widget.query.name_subset is False
        widget.criteria_subset.setChecked(True)
        assert widget.query.name_subset is True
    else:
        widget.criteria_subset.setChecked(True)
        assert widget.query.name_subset is True
        widget.criteria_any.setChecked(True)
        assert widget.query.name_subset is False


def test_equal_subset_disabled_save(qtbot: QtBot) -> None:
    """Test save settings with no options."""
    widget, model = _setup_widget("test_equal_subset_disabled_save", enable_equal=False,
                                  enable_subset=False)
    qtbot.addWidget(widget)

    test_selection = [model.item_list[0], model.item_list[2]]
    widget.criteria.set_selection(test_selection)

    expected_settings: Final = {
        "name": test_selection
    }
    settings: Dict[str, List[str]] = {}
    widget.save(settings)
    assert settings == expected_settings


def test_equal_enabled_subset_disabled_save(qtbot: QtBot) -> None:
    """Test save settings with equal enabled."""
    widget, model = _setup_widget("test_equal_enabled_subset_disabled_save", enable_equal=True,
                                  enable_subset=False)
    qtbot.addWidget(widget)

    test_selection = [model.item_list[0], model.item_list[2]]
    widget.criteria_equal.setChecked(not EQUAL_DEFAULT_CHECKED)
    widget.criteria.set_selection(test_selection)

    expected_settings: Final = {
        "name": test_selection,
        "name_equal": (not EQUAL_DEFAULT_CHECKED)
    }
    settings: Dict[str, Union[List[str], bool]] = {}
    widget.save(settings)
    assert settings == expected_settings


def test_equal_disabled_subset_enabled_save(qtbot: QtBot) -> None:
    """Test save settings with subset enabled."""
    widget, model = _setup_widget("test_equal_disabled_subset_enabled_save", enable_equal=False,
                                  enable_subset=True)
    qtbot.addWidget(widget)

    test_selection = [model.item_list[0], model.item_list[2]]
    widget.criteria_subset.setChecked(not SUBSET_DEFAULT_CHECKED)
    widget.criteria.set_selection(test_selection)

    expected_settings: Final = {
        "name": test_selection,
        "name_subset": (not SUBSET_DEFAULT_CHECKED)
    }
    settings: Dict[str, Union[List[str], bool]] = {}
    widget.save(settings)
    assert settings == expected_settings


def test_equal_subset_enabled_save(qtbot: QtBot) -> None:
    """Test save settings with equal and subset enabled."""
    widget, model = _setup_widget("test_equal_subset_enabled_save", enable_equal=True,
                                  enable_subset=True)
    qtbot.addWidget(widget)

    test_selection = [model.item_list[0], model.item_list[2]]
    widget.criteria_subset.setChecked(True)
    widget.criteria.set_selection(test_selection)

    expected_settings: Final = {
        "name": test_selection,
        "name_equal": False,
        "name_subset": True
    }
    settings: Dict[str, Union[List[str], bool]] = {}
    widget.save(settings)
    assert settings == expected_settings


def test_equal_subset_disabled_load(qtbot: QtBot) -> None:
    """Test load settings with no options."""
    widget, model = _setup_widget("test_equal_subset_disabled_load", enable_equal=False,
                                  enable_subset=False)
    qtbot.addWidget(widget)

    test_selection = [model.item_list[0], model.item_list[2]]
    widget.criteria.set_selection(test_selection)

    settings: Final = {
        "name": test_selection
    }
    widget.load(settings)
    assert list(widget.criteria.selection()) == test_selection
    assert widget.query.name == test_selection


def test_equal_enabled_subset_disabled_load(qtbot: QtBot) -> None:
    """Test load settings with equal enabled."""
    widget, model = _setup_widget("test_equal_enabled_subset_disabled_load", enable_equal=True,
                                  enable_subset=False)
    qtbot.addWidget(widget)

    test_selection = [model.item_list[0], model.item_list[2]]
    widget.criteria_equal.setChecked(not EQUAL_DEFAULT_CHECKED)
    widget.criteria.set_selection(test_selection)

    settings: Final = {
        "name": test_selection,
        "name_equal": True
    }
    widget.load(settings)
    assert list(widget.criteria.selection()) == test_selection
    assert widget.query.name == test_selection
    assert widget.criteria_equal.isChecked() is True
    assert widget.query.name_equal is True


def test_equal_disabled_subset_enabled_load(qtbot: QtBot) -> None:
    """Test load settings with subset enabled."""
    widget, model = _setup_widget("test_equal_disabled_subset_enabled_load", enable_equal=False,
                                  enable_subset=True)
    qtbot.addWidget(widget)

    test_selection = [model.item_list[0], model.item_list[2]]
    widget.criteria_subset.setChecked(not SUBSET_DEFAULT_CHECKED)
    widget.criteria.set_selection(test_selection)

    settings: Final = {
        "name": test_selection,
        "name_subset": True
    }
    widget.load(settings)
    assert list(widget.criteria.selection()) == test_selection
    assert widget.criteria_subset.isChecked() is True
    assert widget.query.name == test_selection
    assert widget.query.name_subset is True


def test_equal_subset_enabled_load(qtbot: QtBot) -> None:
    """Test load settings with equal and subset enabled."""
    widget, model = _setup_widget("test_equal_subset_enabled_load", enable_equal=True,
                                  enable_subset=True)
    qtbot.addWidget(widget)

    test_selection = [model.item_list[0], model.item_list[2]]
    widget.criteria_subset.setChecked(True)
    widget.criteria.set_selection(test_selection)

    settings: Final = {
        "name": test_selection,
        "name_equal": False,
        "name_subset": True
    }
    widget.load(settings)
    assert list(widget.criteria.selection()) == test_selection
    assert widget.criteria_equal.isChecked() is False
    assert widget.criteria_subset.isChecked() is True
    assert widget.query.name == test_selection
    assert widget.query.name_equal is False
    assert widget.query.name_subset is True
