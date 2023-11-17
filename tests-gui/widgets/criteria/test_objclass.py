# SPDX-License-Identifier: GPL-2.0-only
from typing import cast

import pytest
from pytestqt.qtbot import QtBot

from setoolsgui.widgets.criteria.objclass import ObjClassCriteriaWidget
from setoolsgui.widgets.models import ObjClassTable


@pytest.fixture
def widget(mock_query, request: pytest.FixtureRequest, qtbot: QtBot) -> ObjClassCriteriaWidget:
    """Pytest fixture to set up the widget."""
    marker = request.node.get_closest_marker("obj_args")
    kwargs = marker.kwargs if marker else {}
    w = ObjClassCriteriaWidget(request.node.name, mock_query, "name", **kwargs)
    qtbot.addWidget(w)
    w.show()
    return w


def test_base_settings(widget: ObjClassCriteriaWidget, mock_query) -> None:
    """Test base properties of widget."""
    model = cast(ObjClassTable, widget.criteria.model())
    assert model.item_list == sorted(mock_query.policy.classes())
