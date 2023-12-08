# SPDX-License-Identifier: GPL-2.0-only
import typing

from PyQt6 import QtWidgets
import pytest
from pytestqt.qtbot import QtBot

import setools
from setoolsgui.widgets.objclassquery import ObjClassQueryTab


@pytest.fixture
def widget(mock_policy, request: pytest.FixtureRequest, qtbot: QtBot) -> ObjClassQueryTab:
    """Pytest fixture to set up the widget."""
    marker = request.node.get_closest_marker("obj_args")
    kwargs = marker.kwargs if marker else {}
    w = ObjClassQueryTab(mock_policy, **kwargs)
    qtbot.addWidget(w)
    w.show()
    return w


def test_docs(widget: ObjClassQueryTab) -> None:
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


def test_layout(widget: ObjClassQueryTab) -> None:
    """Test the layout of the criteria frame."""
    name, perms = widget.criteria

    assert widget.criteria_frame_layout.columnCount() == 2
    assert widget.criteria_frame_layout.rowCount() == 2
    assert widget.criteria_frame_layout.itemAtPosition(0, 0).widget() == name
    assert widget.criteria_frame_layout.itemAtPosition(0, 1).widget() == perms
    assert widget.criteria_frame_layout.itemAtPosition(1, 0).widget() == widget.buttonBox
    assert widget.criteria_frame_layout.itemAtPosition(1, 1).widget() == widget.buttonBox


def test_criteria_mapping(widget: ObjClassQueryTab) -> None:
    """Test that widgets save to the correct query fields."""
    name, perms = widget.criteria

    assert isinstance(widget.query, setools.ObjClassQuery)
    assert name.attrname == "name"
    assert perms.attrname == "perms"
