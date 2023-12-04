# SPDX-License-Identifier: GPL-2.0-only
import pytest
from pytestqt.qtbot import QtBot

from setools import TERuletype

from setoolsgui.widgets.criteria.teruletype import TERuleType


@pytest.fixture
def widget(mock_query, request: pytest.FixtureRequest, qtbot: QtBot) -> TERuleType:
    """Pytest fixture to set up the widget."""
    marker = request.node.get_closest_marker("obj_args")
    kwargs = marker.kwargs if marker else {}
    w = TERuleType(request.node.name, mock_query, "checkboxes", **kwargs)
    qtbot.addWidget(w)
    w.show()
    return w


def test_base_settings(widget: TERuleType) -> None:
    """Test base properties of TERuleTypeCriteriaWidget."""
    assert len(widget.criteria) == len(TERuletype)
    assert not widget.criteria["neverallow"].isEnabled()
    assert not widget.criteria["neverallowxperm"].isEnabled()
