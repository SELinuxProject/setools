# SPDX-License-Identifier: GPL-2.0-only
from PyQt6 import QtCore
import pytest
from pytestqt.qtbot import QtBot

from setoolsgui.widgets.criteria.boolean import (BooleanListCriteriaWidget,
                                                 BooleanNameCriteriaWidget)
from setoolsgui.widgets.models.table import SEToolsTableModel


@pytest.fixture
def list_widget(mock_query, request: pytest.FixtureRequest,
                qtbot: QtBot) -> BooleanListCriteriaWidget:
    """Pytest fixture to set up the Boolean list widget."""
    marker = request.node.get_closest_marker("obj_args")
    kwargs = marker.kwargs if marker else {}
    w = BooleanListCriteriaWidget(request.node.name, mock_query, "name", **kwargs)
    qtbot.addWidget(w)
    w.show()
    return w


@pytest.fixture
def name_widget(mock_query, request: pytest.FixtureRequest,
                qtbot: QtBot) -> BooleanNameCriteriaWidget:
    """Pytest fixture to set up the Boolean name widget."""
    marker = request.node.get_closest_marker("obj_args")
    kwargs = marker.kwargs if marker else {}
    w = BooleanNameCriteriaWidget(request.node.name, mock_query, "name", **kwargs)
    qtbot.addWidget(w)
    w.show()
    return w


def test_bool_list(list_widget: BooleanListCriteriaWidget, mock_query) -> None:
    """Test Boolean name list widget."""
    model = list_widget.criteria.model()
    assert isinstance(model, SEToolsTableModel)
    assert sorted(mock_query.policy.bools()) == model.item_list


def test_bool_name(name_widget: BooleanNameCriteriaWidget, mock_query) -> None:
    """Test Boolean name line edit widget."""
    model = name_widget.criteria.completer().model()
    assert isinstance(model, QtCore.QStringListModel)
    assert sorted(b.name for b in mock_query.policy.bools()) == model.stringList()
