# SPDX-License-Identifier: GPL-2.0-only
import pytest
from pytestqt.qtbot import QtBot

from setoolsgui.widgets.criteria.permission import PermissionList


@pytest.fixture
def widget(mock_query, request: pytest.FixtureRequest, qtbot: QtBot) -> PermissionList:
    """Pytest fixture to set up the widget."""
    marker = request.node.get_closest_marker("obj_args")
    kwargs = marker.kwargs if marker else {}
    w = PermissionList(request.node.name, mock_query, "name", **kwargs)
    qtbot.addWidget(w)
    w.show()
    return w


def test_base_settings(widget: PermissionList) -> None:
    """Test base properties of widget."""
    assert widget.perm_model.item_list == ["bar_perm1", "bar_perm2", "common_perm", "foo_perm1",
                                           "foo_perm2"]


def test_set_classes(widget: PermissionList, mock_query) -> None:
    """Test list contents based on class filtering."""
    widget.set_classes([mock_query.policy.classes()[0]])
    assert widget.perm_model.item_list == ["common_perm", "foo_perm1", "foo_perm2"]

    widget.set_classes(list(mock_query.policy.classes()))
    assert widget.perm_model.item_list == ["common_perm"]
