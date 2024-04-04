# SPDX-License-Identifier: GPL-2.0-only
from PyQt6 import QtCore
import pytest
from pytestqt.qtbot import QtBot

from setoolsgui.widgets import criteria


@pytest.fixture
def widget(mock_query, request: pytest.FixtureRequest, qtbot: QtBot) -> criteria.CommonName:
    """Pytest fixture to set up the widget."""
    marker = request.node.get_closest_marker("obj_args")
    kwargs = marker.kwargs if marker else {}
    w = criteria.CommonName(request.node.name, mock_query, "name", **kwargs)
    qtbot.addWidget(w)
    w.show()
    return w


def test_base_settings(widget: criteria.CommonName, mock_query) -> None:
    """Test base properties of widget."""
    model = widget.criteria.completer().model()
    assert isinstance(model, QtCore.QStringListModel)
    assert sorted(c.name for c in mock_query.policy.commons()) == model.stringList()
