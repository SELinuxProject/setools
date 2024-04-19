# SPDX-License-Identifier: GPL-2.0-only
from typing import cast

from PyQt6 import QtCore
import pytest
from pytestqt.qtbot import QtBot

from setoolsgui.widgets.criteria.objclass import ObjClassList, ObjClassName
from setoolsgui.widgets.models import ObjClassTable


@pytest.fixture
def list_widget(mock_query, request: pytest.FixtureRequest, qtbot: QtBot) -> ObjClassList:
    """Pytest fixture to set up the widget."""
    marker = request.node.get_closest_marker("obj_args")
    kwargs = marker.kwargs if marker else {}
    w = ObjClassList(request.node.name, mock_query, "name", **kwargs)
    qtbot.addWidget(w)
    w.show()
    return w


@pytest.fixture
def name_widget(mock_query, request: pytest.FixtureRequest, qtbot: QtBot) -> ObjClassName:
    """Pytest fixture to set up the widget."""
    marker = request.node.get_closest_marker("obj_args")
    kwargs = marker.kwargs if marker else {}
    w = ObjClassName(request.node.name, mock_query, "name", **kwargs)
    qtbot.addWidget(w)
    w.show()
    return w


def test_list_base_settings(list_widget: ObjClassList, mock_query) -> None:
    """Test base properties of list widget."""
    model = cast(ObjClassTable, list_widget.criteria.model())
    assert model.item_list == sorted(mock_query.policy.classes())


def test_name_base_settings(name_widget: ObjClassName, mock_query) -> None:
    """Test base properties of name widget."""
    model = name_widget.criteria.completer().model()
    assert isinstance(model, QtCore.QStringListModel)
    assert sorted(r.name for r in mock_query.policy.classes()) == model.stringList()
