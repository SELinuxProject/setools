# SPDX-License-Identifier: GPL-2.0-only
from typing import Dict, Final, Union
from unittest.mock import PropertyMock

from PyQt6 import QtGui
import pytest
from pytestqt.qtbot import QtBot

from setoolsgui.widgets.criteria.criteria import OptionsPlacement
from setoolsgui.widgets.criteria.name import NameWidget, REGEX_DEFAULT_CHECKED


@pytest.fixture
def widget(mock_query, request: pytest.FixtureRequest, qtbot: QtBot) -> NameWidget:
    """Pytest fixture to set up the widget."""
    marker = request.node.get_closest_marker("obj_args")
    kwargs = marker.kwargs if marker else {}
    if "completion" not in kwargs:
        kwargs["completion"] = []
    if "validation" not in kwargs:
        kwargs["validation"] = "[a-z]*"

    w = NameWidget(request.node.name, mock_query, "name", **kwargs)
    qtbot.addWidget(w)
    w.show()
    return w


def test_base_settings(widget: NameWidget) -> None:
    """Test base properties of widget."""
    assert widget.criteria.objectName() == "name"
    assert widget.criteria.isClearButtonEnabled()
    assert not widget.criteria.isReadOnly()
    assert widget.criteria_regex.toolTip()
    assert widget.criteria_regex.whatsThis()


@pytest.mark.obj_args(completion=["foo", "bar"])
def test_completer(widget: NameWidget) -> None:
    """Test completer is correctly set up."""
    widget.criteria.completer().setCompletionPrefix("fo")
    assert widget.criteria.completer().currentCompletion() == "foo"
    widget.criteria.completer().setCompletionPrefix("b")
    assert widget.criteria.completer().currentCompletion() == "bar"


def test_valid_text_entry(widget: NameWidget, mock_query) -> None:
    """Test successful text entry."""
    widget.criteria.clear()
    widget.criteria.editingFinished.emit()
    widget.criteria.insert("textinput")
    widget.criteria.editingFinished.emit()
    assert mock_query.name == "textinput"
    assert widget.error_text.pixmap().isNull()
    assert not widget.error_text.toolTip()
    assert not widget.has_errors


def test_query_exception_text_entry(widget: NameWidget, mock_query) -> None:
    """Test error text entry from query exception."""
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


def test_invalid_text_entry(widget: NameWidget, mock_query) -> None:
    """Test invalid text entry stopped by validator."""
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


@pytest.mark.obj_args(options_placement=OptionsPlacement.RIGHT, enable_regex=False)
def test_regex_disabled_layout_opt_right(widget: NameWidget) -> None:
    """Test layout for no regex option, options placement right."""
    # validate widget item positions
    assert widget.top_layout.itemAtPosition(0, 0).widget() == widget.criteria
    assert widget.top_layout.itemAtPosition(0, 1) is None
    assert widget.top_layout.itemAtPosition(1, 0).widget() == widget.error_text
    assert widget.top_layout.itemAtPosition(1, 1) is None


@pytest.mark.obj_args(options_placement=OptionsPlacement.BELOW, enable_regex=False)
def test_regex_disabled_layout_opt_below(widget: NameWidget) -> None:
    """Test layout for no regex option, options placement below."""
    # validate widget item positions
    assert widget.top_layout.itemAtPosition(0, 0).widget() == widget.criteria
    assert widget.top_layout.itemAtPosition(0, 1).widget() == widget.error_text
    assert widget.top_layout.itemAtPosition(1, 0) is None
    assert widget.top_layout.itemAtPosition(1, 1) is None


@pytest.mark.obj_args(options_placement=OptionsPlacement.RIGHT, enable_regex=True)
def test_regex_enabled_layout_opt_right(widget: NameWidget) -> None:
    """Test layout for regex option placed on right."""
    assert widget.criteria_regex.objectName() == "name_regex"
    # validate widget item positions
    assert widget.top_layout.itemAtPosition(0, 0).widget() == widget.criteria
    assert widget.top_layout.itemAtPosition(0, 1).widget() == widget.criteria_regex
    assert widget.top_layout.itemAtPosition(1, 0).widget() == widget.error_text
    assert widget.top_layout.itemAtPosition(1, 1) is None


@pytest.mark.obj_args(options_placement=OptionsPlacement.BELOW, enable_regex=True)
def test_regex_enabled_layout_opt_below(widget: NameWidget) -> None:
    """Test layout for regex option placed below."""
    assert widget.criteria_regex.objectName() == "name_regex"
    # validate widget item positions
    assert widget.top_layout.itemAtPosition(0, 0).widget() == widget.criteria
    assert widget.top_layout.itemAtPosition(1, 0).widget() == widget.criteria_regex
    assert widget.top_layout.itemAtPosition(0, 1).widget() == widget.error_text
    assert widget.top_layout.itemAtPosition(1, 1) is None


@pytest.mark.obj_args(enable_regex=True)
def test_regex_toggling(widget: NameWidget, mock_query) -> None:
    """Test regex toggling is reflected in the query."""
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


@pytest.mark.obj_args(enable_regex=False)
def test_noregex_save(widget: NameWidget, request: pytest.FixtureRequest) -> None:
    widget.criteria.clear()
    widget.criteria.editingFinished.emit()
    widget.criteria.setText(request.node.name)
    widget.criteria.editingFinished.emit()

    settings: Dict[str, Union[str, bool]] = {}
    expected_settings: Final = {
        "name": request.node.name
    }
    widget.save(settings)
    assert settings == expected_settings


@pytest.mark.obj_args(enable_regex=True)
def test_regex_save(widget: NameWidget, request: pytest.FixtureRequest) -> None:
    widget.criteria_regex.setChecked(not REGEX_DEFAULT_CHECKED)
    widget.criteria.clear()
    widget.criteria.editingFinished.emit()
    widget.criteria.setText(request.node.name)
    widget.criteria.editingFinished.emit()

    settings: Dict[str, Union[str, bool]] = {}
    expected_settings: Final = {
        "name": request.node.name,
        "name_regex": not REGEX_DEFAULT_CHECKED
    }
    widget.save(settings)
    assert settings == expected_settings


@pytest.mark.obj_args(enable_regex=False)
def test_noregex_load(widget: NameWidget, mock_query,
                      request: pytest.FixtureRequest) -> None:
    settings: Final = {
        "name": request.node.name
    }
    widget.load(settings)

    assert widget.criteria.text() == request.node.name
    assert mock_query.name == request.node.name


@pytest.mark.obj_args(enable_regex=True)
def test_regex_load(widget: NameWidget, mock_query,
                    request: pytest.FixtureRequest) -> None:
    settings: Final = {
        "name": request.node.name,
        "name_regex": not REGEX_DEFAULT_CHECKED
    }
    widget.load(settings)

    assert widget.criteria.text() == request.node.name
    assert mock_query.name == request.node.name
    assert widget.criteria_regex.isChecked() == (not REGEX_DEFAULT_CHECKED)
    assert mock_query.name_regex == (not REGEX_DEFAULT_CHECKED)
