# SPDX-License-Identifier: GPL-2.0-only
from pytestqt.qtbot import QtBot

from setoolsgui.widgets.criteria.permission import PermissionCriteriaWidget

from .util import build_mock_query


def test_base_settings(qtbot: QtBot) -> None:
    """Test base properties of widget."""
    mock_query = build_mock_query()
    widget = PermissionCriteriaWidget("test_base_settings", mock_query, "name")
    qtbot.addWidget(widget)

    assert widget.perm_model.item_list == ["bar_perm1", "bar_perm2", "common_perm", "foo_perm1",
                                           "foo_perm2"]


def test_set_classes(qtbot: QtBot) -> None:
    """Test list contents based on class filtering."""
    mock_query = build_mock_query()
    widget = PermissionCriteriaWidget("test_set_classes", mock_query, "name")
    qtbot.addWidget(widget)

    widget.set_classes([mock_query.policy.classes()[0]])
    assert widget.perm_model.item_list == ["common_perm", "foo_perm1", "foo_perm2"]

    widget.set_classes(list(mock_query.policy.classes()))
    assert widget.perm_model.item_list == ["common_perm"]
