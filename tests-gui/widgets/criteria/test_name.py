# SPDX-License-Identifier: GPL-2.0-only
from typing import Dict, Final, Union
from unittest.mock import PropertyMock

from PyQt6 import QtGui
from pytestqt.qtbot import QtBot

from setoolsgui.widgets.criteria.criteria import OptionsPlacement
from setoolsgui.widgets.criteria.name import NameCriteriaWidget, REGEX_DEFAULT_CHECKED

from .util import build_mock_query


def test_base_settings(qtbot: QtBot) -> None:
    """Test base properties of widget."""
    mock_query = build_mock_query()
    widget = NameCriteriaWidget("test_base_settings", mock_query, "name", [], "[a-z]*")
    qtbot.addWidget(widget)

    assert widget.criteria.objectName() == "name"
    assert widget.criteria.isClearButtonEnabled()
    assert not widget.criteria.isReadOnly()
    assert widget.criteria_regex.toolTip()
    assert widget.criteria_regex.whatsThis()


def test_completer(qtbot: QtBot) -> None:
    """Test completer is correctly set up."""
    mock_query = build_mock_query()
    widget = NameCriteriaWidget("test_base_settings", mock_query, "name", ["foo", "bar"], "[a-z]*")
    qtbot.addWidget(widget)

    widget.criteria.completer().setCompletionPrefix("fo")
    assert widget.criteria.completer().currentCompletion() == "foo"
    widget.criteria.completer().setCompletionPrefix("b")
    assert widget.criteria.completer().currentCompletion() == "bar"


def test_valid_text_entry(qtbot: QtBot) -> None:
    """Test successful text entry."""
    mock_query = build_mock_query()
    widget = NameCriteriaWidget("test_valid_text_entry", mock_query, "name", [], "[a-z]*")
    qtbot.addWidget(widget)

    widget.criteria.clear()
    widget.criteria.editingFinished.emit()
    widget.criteria.insert("textinput")
    widget.criteria.editingFinished.emit()
    assert mock_query.name == "textinput"
    assert widget.error_text.pixmap().isNull()
    assert not widget.error_text.toolTip()
    assert not widget.has_errors


def test_query_exception_text_entry(qtbot: QtBot) -> None:
    """Test error text entry from query exception."""
    mock_query = build_mock_query()
    widget = NameCriteriaWidget("test_query_exception_text_entry", mock_query, "name", [],
                                "[a-z]*")
    qtbot.addWidget(widget)

    # exception from query
    widget.criteria.clear()
    widget.criteria.editingFinished.emit()
    error_message = "bad value"
    type(mock_query).name = PropertyMock(side_effect=ValueError(error_message))
    widget.criteria.insert("exceptiontext")
    widget.criteria.editingFinished.emit()
    assert isinstance(widget.error_text.pixmap(), QtGui.QPixmap)
    assert error_message in widget.error_text.toolTip()
    assert widget.has_errors


def test_invalid_text_entry(qtbot: QtBot) -> None:
    """Test invalid text entry stopped by validator."""
    mock_query = build_mock_query()
    widget = NameCriteriaWidget("test_invalid_text_entry", mock_query, "name", [], "[a-z]*")
    qtbot.addWidget(widget)

    # note regex doesn't have a validator.
    widget.criteria_regex.setChecked(False)
    widget.criteria.clear()
    widget.criteria.editingFinished.emit()
    widget.criteria.insert("textinput&")
    widget.criteria.editingFinished.emit()
    assert not mock_query.name
    assert widget.error_text.pixmap().isNull()
    assert not widget.error_text.toolTip()
    # not checking has_errors since it may not be set
    # depending on the UI state since the validator stops
    # invalid characters


def test_regex_disabled_layout_opt_right(qtbot: QtBot) -> None:
    """Test layout for no regex option, options placement right."""
    mock_query = build_mock_query()
    widget = NameCriteriaWidget("test_regex_disabled_layout", mock_query, "name", [], "[a-z]*",
                                options_placement=OptionsPlacement.RIGHT, enable_regex=False)
    qtbot.addWidget(widget)

    # validate widget item positions
    assert widget.top_layout.itemAtPosition(0, 0).widget() == widget.criteria
    assert widget.top_layout.itemAtPosition(0, 1) is None
    assert widget.top_layout.itemAtPosition(1, 0).widget() == widget.error_text
    assert widget.top_layout.itemAtPosition(1, 1) is None


def test_regex_disabled_layout_opt_below(qtbot: QtBot) -> None:
    """Test layout for no regex option, options placement below."""
    mock_query = build_mock_query()
    widget = NameCriteriaWidget("test_regex_disabled_layout", mock_query, "name", [], "[a-z]*",
                                options_placement=OptionsPlacement.BELOW, enable_regex=False)
    qtbot.addWidget(widget)

    # validate widget item positions
    assert widget.top_layout.itemAtPosition(0, 0).widget() == widget.criteria
    assert widget.top_layout.itemAtPosition(0, 1).widget() == widget.error_text
    assert widget.top_layout.itemAtPosition(1, 0) is None
    assert widget.top_layout.itemAtPosition(1, 1) is None


def test_regex_enabled_layout_opt_right(qtbot: QtBot) -> None:
    """Test layout for regex option placed on right."""
    mock_query = build_mock_query()
    widget = NameCriteriaWidget("test_regex_enabled_layout", mock_query, "name", [], "[a-z]*",
                                options_placement=OptionsPlacement.RIGHT, enable_regex=True)
    qtbot.addWidget(widget)

    assert widget.criteria_regex.objectName() == "name_regex"
    # validate widget item positions
    assert widget.top_layout.itemAtPosition(0, 0).widget() == widget.criteria
    assert widget.top_layout.itemAtPosition(0, 1).widget() == widget.criteria_regex
    assert widget.top_layout.itemAtPosition(1, 0).widget() == widget.error_text
    assert widget.top_layout.itemAtPosition(1, 1) is None


def test_regex_enabled_layout_opt_below(qtbot: QtBot) -> None:
    """Test layout for regex option placed below."""
    mock_query = build_mock_query()
    widget = NameCriteriaWidget("test_regex_enabled_layout", mock_query, "name", [], "[a-z]*",
                                options_placement=OptionsPlacement.BELOW, enable_regex=True)
    qtbot.addWidget(widget)

    assert widget.criteria_regex.objectName() == "name_regex"
    # validate widget item positions
    assert widget.top_layout.itemAtPosition(0, 0).widget() == widget.criteria
    assert widget.top_layout.itemAtPosition(1, 0).widget() == widget.criteria_regex
    assert widget.top_layout.itemAtPosition(0, 1).widget() == widget.error_text
    assert widget.top_layout.itemAtPosition(1, 1) is None


def test_regex_toggling(qtbot: QtBot) -> None:
    """Test regex toggling is reflected in the query."""
    mock_query = build_mock_query()
    widget = NameCriteriaWidget("test_regex_toggling", mock_query, "name", [], "[a-z]*",
                                enable_regex=True)
    qtbot.addWidget(widget)

    # test toggling based on the initial state
    assert mock_query.name_regex is REGEX_DEFAULT_CHECKED
    if REGEX_DEFAULT_CHECKED:
        widget.criteria_regex.setChecked(False)
        assert mock_query.name_regex is False
        widget.criteria_regex.setChecked(True)
        assert mock_query.name_regex is True
    else:
        widget.criteria_regex.setChecked(True)
        assert mock_query.name_regex is True
        widget.criteria_regex.setChecked(False)
        assert mock_query.name_regex is False


def test_noregex_save(qtbot: QtBot) -> None:
    mock_query = build_mock_query()
    widget = NameCriteriaWidget("test_noregex_save", mock_query, "name", [], "[a-z]*",
                                enable_regex=False)
    qtbot.addWidget(widget)

    widget.criteria.clear()
    widget.criteria.editingFinished.emit()
    widget.criteria.setText("test_noregex_save")
    widget.criteria.editingFinished.emit()

    settings: Dict[str, Union[str, bool]] = {}
    expected_settings: Final = {
        "name": "test_noregex_save"
    }
    widget.save(settings)
    assert settings == expected_settings


def test_regex_save(qtbot: QtBot) -> None:
    mock_query = build_mock_query()
    widget = NameCriteriaWidget("test_regex_save", mock_query, "name", [], "[a-z]*",
                                enable_regex=True)
    qtbot.addWidget(widget)

    widget.criteria_regex.setChecked(not REGEX_DEFAULT_CHECKED)
    widget.criteria.clear()
    widget.criteria.editingFinished.emit()
    widget.criteria.setText("test_regex_save")
    widget.criteria.editingFinished.emit()

    settings: Dict[str, Union[str, bool]] = {}
    expected_settings: Final = {
        "name": "test_regex_save",
        "name_regex": not REGEX_DEFAULT_CHECKED
    }
    widget.save(settings)
    assert settings == expected_settings


def test_noregex_load(qtbot: QtBot) -> None:
    mock_query = build_mock_query()
    widget = NameCriteriaWidget("test_noregex_load", mock_query, "name", [], "[a-z]*",
                                enable_regex=False)
    qtbot.addWidget(widget)

    settings: Final = {
        "name": "test_noregex_load"
    }
    widget.load(settings)

    assert widget.criteria.text() == "test_noregex_load"
    assert mock_query.name == "test_noregex_load"


def test_regex_load(qtbot: QtBot) -> None:
    mock_query = build_mock_query()
    widget = NameCriteriaWidget("test_regex_load", mock_query, "name", [], "[a-z]*",
                                enable_regex=True)
    qtbot.addWidget(widget)

    settings: Final = {
        "name": "test_regex_load",
        "name_regex": not REGEX_DEFAULT_CHECKED
    }
    widget.load(settings)

    assert widget.criteria.text() == "test_regex_load"
    assert mock_query.name == "test_regex_load"
    assert widget.criteria_regex.isChecked() == (not REGEX_DEFAULT_CHECKED)
    assert mock_query.name_regex == (not REGEX_DEFAULT_CHECKED)
