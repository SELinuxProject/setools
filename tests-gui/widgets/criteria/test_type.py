# SPDX-License-Identifier: GPL-2.0-only
from typing import Dict, Union

from PyQt5 import QtGui
from pytestqt.qtbot import QtBot

from setoolsgui.widgets.criteria.type import (TypeOrAttrNameWidget,
                                              INDIRECT_DEFAULT_CHECKED)

from .util import _build_mock_query


def test_base_settings(qtbot: QtBot) -> None:
    mock_query = _build_mock_query()
    widget = TypeOrAttrNameWidget(
        "test_indirect_disabled_layout", mock_query, "name",
        enable_indirect=True, mode=TypeOrAttrNameWidget.Mode.type_or_attribute)
    qtbot.addWidget(widget)

    assert widget.criteria_indirect.toolTip()
    assert widget.criteria_indirect.whatsThis()


def test_indirect_disabled_layout(qtbot: QtBot) -> None:
    """Test layout for no indirect option."""
    mock_query = _build_mock_query()
    widget = TypeOrAttrNameWidget(
        "test_indirect_disabled_layout", mock_query, "name",
        enable_indirect=False, mode=TypeOrAttrNameWidget.Mode.type_only)
    qtbot.addWidget(widget)

    # validate widget item positions
    assert not widget.top_layout.itemAtPosition(1, 2)


def test_indirect_enabled_layout(qtbot: QtBot) -> None:
    """Test layout for indirect option."""
    mock_query = _build_mock_query()
    widget = TypeOrAttrNameWidget(
        "test_indirect_enabled_layout", mock_query, "name",
        enable_indirect=True, mode=TypeOrAttrNameWidget.Mode.type_or_attribute)
    qtbot.addWidget(widget)

    assert widget.criteria_indirect.objectName() == "name_indirect"
    # validate widget item positions
    assert widget.top_layout.itemAtPosition(1, 1).widget() == widget.criteria_indirect


def test_indirect_toggling(qtbot: QtBot) -> None:
    """Test indirect toggling is reflected in the query."""
    mock_query = _build_mock_query()
    widget = TypeOrAttrNameWidget(
        "test_indirect_toggling", mock_query, "name",
        enable_indirect=True, mode=TypeOrAttrNameWidget.Mode.type_or_attribute)
    qtbot.addWidget(widget)

    # test toggling based on the initial state
    assert mock_query.name_indirect is INDIRECT_DEFAULT_CHECKED
    if INDIRECT_DEFAULT_CHECKED:
        widget.criteria_indirect.setChecked(False)
        assert mock_query.name_indirect is False
        widget.criteria_indirect.setChecked(True)
        assert mock_query.name_indirect is True
    else:
        widget.criteria_indirect.setChecked(True)
        assert mock_query.name_indirect is True
        widget.criteria_indirect.setChecked(False)
        assert mock_query.name_indirect is False


def test_noindirect_save(qtbot: QtBot) -> None:
    """Test settings save with indirect disabled."""
    mock_query = _build_mock_query()
    widget = TypeOrAttrNameWidget(
        "test_indirect_toggling", mock_query, "name",
        enable_indirect=False, mode=TypeOrAttrNameWidget.Mode.type_or_attribute,
        enable_regex=False)
    qtbot.addWidget(widget)

    widget.criteria.clear()
    widget.criteria.editingFinished.emit()
    widget.criteria.setText("test_noindirect_save")
    widget.criteria.editingFinished.emit()

    settings: Dict[str, Union[str, bool]] = {}
    expected_settings = {
        "name": "test_noindirect_save"
    }
    widget.save(settings)
    assert settings == expected_settings


def test_indirect_save(qtbot: QtBot) -> None:
    """Test settings save with indirect enabled."""
    mock_query = _build_mock_query()
    widget = TypeOrAttrNameWidget(
        "test_indirect_toggling", mock_query, "name",
        enable_indirect=True, mode=TypeOrAttrNameWidget.Mode.type_or_attribute,
        enable_regex=False)
    qtbot.addWidget(widget)

    widget.criteria_indirect.setChecked(not INDIRECT_DEFAULT_CHECKED)
    widget.criteria.clear()
    widget.criteria.editingFinished.emit()
    widget.criteria.setText("test_indirect_save")
    widget.criteria.editingFinished.emit()

    settings: Dict[str, Union[str, bool]] = {}
    expected_settings = {
        "name": "test_indirect_save",
        "name_indirect": not INDIRECT_DEFAULT_CHECKED
    }
    widget.save(settings)
    assert settings == expected_settings


def test_noindirect_load(qtbot: QtBot) -> None:
    """Test settings load with indirect disabled."""
    mock_query = _build_mock_query()
    widget = TypeOrAttrNameWidget(
        "test_indirect_toggling", mock_query, "name",
        enable_indirect=False, mode=TypeOrAttrNameWidget.Mode.type_or_attribute,
        enable_regex=False)
    qtbot.addWidget(widget)

    settings = {
        "name": "test_noindirect_load"
    }
    widget.load(settings)

    assert widget.criteria.text() == "test_noindirect_load"
    assert mock_query.name == "test_noindirect_load"


def test_indirect_load(qtbot: QtBot) -> None:
    """Test settings load with indirect enabled."""
    mock_query = _build_mock_query()
    widget = TypeOrAttrNameWidget(
        "test_indirect_toggling", mock_query, "name",
        enable_indirect=True, mode=TypeOrAttrNameWidget.Mode.type_or_attribute,
        enable_regex=False)
    qtbot.addWidget(widget)

    settings = {
        "name": "test_indirect_load",
        "name_indirect": not INDIRECT_DEFAULT_CHECKED
    }
    widget.load(settings)

    assert widget.criteria.text() == "test_indirect_load"
    assert mock_query.name == "test_indirect_load"
    assert widget.criteria_indirect.isChecked() == (not INDIRECT_DEFAULT_CHECKED)
    assert mock_query.name_indirect == (not INDIRECT_DEFAULT_CHECKED)
