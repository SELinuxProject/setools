# SPDX-License-Identifier: GPL-2.0-only
import typing

from PyQt6 import QtWidgets
import pytest
from pytestqt.qtbot import QtBot

import setools
from setoolsgui.widgets.userquery import UserQueryTab


@pytest.fixture
def widget(mock_policy, request: pytest.FixtureRequest, qtbot: QtBot) -> UserQueryTab:
    """Pytest fixture to set up the widget."""
    marker = request.node.get_closest_marker("obj_args")
    kwargs = marker.kwargs if marker else {}
    w = UserQueryTab(mock_policy, **kwargs)
    qtbot.addWidget(w)
    w.show()
    return w


def test_docs(widget: UserQueryTab) -> None:
    """Check that docs are provided for the widget."""
    assert widget.whatsThis()
    assert widget.table_results.whatsThis()
    assert widget.raw_results.whatsThis()

    for w in widget.criteria:
        assert w.toolTip()
        assert w.whatsThis()

    results = typing.cast(QtWidgets.QTabWidget, widget.results)
    for index in range(results.count()):
        assert results.tabWhatsThis(index)


def test_layout(widget: UserQueryTab) -> None:
    """Test the layout of the criteria frame."""
    name, roles, lvl, rng = widget.criteria

    assert widget.criteria_frame_layout.columnCount() == 2
    assert widget.criteria_frame_layout.rowCount() == 3
    assert widget.criteria_frame_layout.itemAtPosition(0, 0).widget() == name
    assert widget.criteria_frame_layout.itemAtPosition(0, 1).widget() == roles
    assert widget.criteria_frame_layout.itemAtPosition(1, 0).widget() == lvl
    assert widget.criteria_frame_layout.itemAtPosition(1, 1).widget() == rng
    assert widget.criteria_frame_layout.itemAtPosition(2, 0).widget() == widget.buttonBox
    assert widget.criteria_frame_layout.itemAtPosition(2, 1).widget() == widget.buttonBox


def test_criteria_mapping(widget: UserQueryTab) -> None:
    """Test that widgets save to the correct query fields."""
    name, roles, lvl, rng = widget.criteria

    assert isinstance(widget.query, setools.UserQuery)
    assert name.attrname == "name"
    assert roles.attrname == "roles"
    assert lvl.attrname == "level"
    assert rng.attrname == "range_"
