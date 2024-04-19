# SPDX-License-Identifier: GPL-2.0-only
from typing import Dict, Union

import pytest
from pytestqt.qtbot import QtBot

from setoolsgui.widgets.criteria.type import (TypeName,
                                              INDIRECT_DEFAULT_CHECKED)


@pytest.fixture
def widget(mock_query, request: pytest.FixtureRequest, qtbot: QtBot) -> TypeName:
    """Pytest fixture to set up the widget."""
    marker = request.node.get_closest_marker("obj_args")
    kwargs = marker.kwargs if marker else {}
    w = TypeName(request.node.name, mock_query, "name", **kwargs)
    qtbot.addWidget(w)
    w.show()
    return w


@pytest.mark.obj_args(enable_indirect=True)
def test_base_settings(widget: TypeName) -> None:
    """Test base properties of TypeName."""
    assert widget.criteria_indirect.toolTip()
    assert widget.criteria_indirect.whatsThis()


@pytest.mark.obj_args(enable_indirect=False)
def test_indirect_disabled_layout(widget: TypeName) -> None:
    """Test layout for no indirect option."""
    # validate widget item positions
    assert not widget.top_layout.itemAtPosition(1, 2)


@pytest.mark.obj_args(enable_indirect=True)
def test_indirect_enabled_layout(widget: TypeName) -> None:
    """Test layout for indirect option."""
    assert widget.criteria_indirect.objectName() == "name_indirect"
    # validate widget item positions
    assert widget.top_layout.itemAtPosition(1, 1).widget() == widget.criteria_indirect


@pytest.mark.obj_args(enable_indirect=True)
def test_indirect_toggling(widget: TypeName, mock_query) -> None:
    """Test indirect toggling is reflected in the query."""
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


@pytest.mark.obj_args(enable_indirect=False, enable_regex=False)
def test_noindirect_save(widget: TypeName,  request: pytest.FixtureRequest) -> None:
    """Test settings save with indirect disabled."""
    widget.criteria.clear()
    widget.criteria.editingFinished.emit()
    widget.criteria.setText(request.node.name)
    widget.criteria.editingFinished.emit()

    settings: Dict[str, Union[str, bool]] = {}
    expected_settings = {
        "name": request.node.name
    }
    widget.save(settings)
    assert settings == expected_settings


@pytest.mark.obj_args(enable_indirect=True, enable_regex=False)
def test_indirect_save(widget: TypeName, request: pytest.FixtureRequest) -> None:
    """Test settings save with indirect enabled."""
    widget.criteria_indirect.setChecked(not INDIRECT_DEFAULT_CHECKED)
    widget.criteria.clear()
    widget.criteria.editingFinished.emit()
    widget.criteria.setText(request.node.name)
    widget.criteria.editingFinished.emit()

    settings: Dict[str, Union[str, bool]] = {}
    expected_settings = {
        "name": request.node.name,
        "name_indirect": not INDIRECT_DEFAULT_CHECKED
    }
    widget.save(settings)
    assert settings == expected_settings


@pytest.mark.obj_args(enable_indirect=False, enable_regex=False)
def test_noindirect_load(widget: TypeName, mock_query,
                         request: pytest.FixtureRequest) -> None:
    """Test settings load with indirect disabled."""
    settings = {
        "name": request.node.name
    }
    widget.load(settings)

    assert widget.criteria.text() == request.node.name
    assert mock_query.name == request.node.name


@pytest.mark.obj_args(enable_indirect=True, enable_regex=False)
def test_indirect_load(widget: TypeName, mock_query,
                       request: pytest.FixtureRequest) -> None:
    """Test settings load with indirect enabled."""
    settings = {
        "name": request.node.name,
        "name_indirect": not INDIRECT_DEFAULT_CHECKED
    }
    widget.load(settings)

    assert widget.criteria.text() == request.node.name
    assert mock_query.name == request.node.name
    assert widget.criteria_indirect.isChecked() == (not INDIRECT_DEFAULT_CHECKED)
    assert mock_query.name_indirect == (not INDIRECT_DEFAULT_CHECKED)
