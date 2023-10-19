# SPDX-License-Identifier: GPL-2.0-only
from typing import cast

from pytestqt.qtbot import QtBot

from setoolsgui.widgets.criteria.objclass import ObjClassCriteriaWidget
from setoolsgui.widgets.models import ObjClassTable

from .util import build_mock_query


def test_base_settings(qtbot: QtBot) -> None:
    """Test base properties of widget."""
    mock_query = build_mock_query()
    widget = ObjClassCriteriaWidget("test_base_settings", mock_query, "name")
    qtbot.addWidget(widget)

    model = cast(ObjClassTable, widget.criteria.model())
    assert model.item_list == sorted(mock_query.policy.classes())
