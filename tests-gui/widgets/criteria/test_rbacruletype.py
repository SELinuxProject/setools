# SPDX-License-Identifier: GPL-2.0-only
import pytest
from pytestqt.qtbot import QtBot

from setools import RBACRuletype

from setoolsgui.widgets.criteria.rbacruletype import RBACRuleType


@pytest.fixture
def widget(mock_query, request: pytest.FixtureRequest, qtbot: QtBot) -> RBACRuleType:
    """Pytest fixture to set up the widget."""
    marker = request.node.get_closest_marker("obj_args")
    kwargs = marker.kwargs if marker else {}
    w = RBACRuleType(request.node.name, mock_query, "checkboxes", **kwargs)
    qtbot.addWidget(w)
    w.show()
    return w


def test_base_settings(widget: RBACRuleType) -> None:
    """Test base properties of widget."""
    assert len(widget.criteria) == len(RBACRuletype)
