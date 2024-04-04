# SPDX-License-Identifier: GPL-2.0-only
from typing import cast

from PyQt6 import QtWidgets
import pytest
from pytestqt.qtbot import QtBot

from setoolsgui.widgets.terulequery import TERuleQueryTab


@pytest.fixture
def widget(mock_policy, request: pytest.FixtureRequest, qtbot: QtBot) -> TERuleQueryTab:
    """Pytest fixture to set up the widget."""
    marker = request.node.get_closest_marker("obj_args")
    kwargs = marker.kwargs if marker else {}
    w = TERuleQueryTab(mock_policy, **kwargs)
    qtbot.addWidget(w)
    w.show()
    return w


def test_docs(widget: TERuleQueryTab) -> None:
    """Check that docs are provided for the widget."""
    assert widget.whatsThis()
    assert widget.table_results.whatsThis()
    assert widget.raw_results.whatsThis()

    for w in widget.criteria:
        assert w.toolTip()
        assert w.whatsThis()

    results = cast(QtWidgets.QTabWidget, widget.results)
    for index in range(results.count()):
        assert results.tabWhatsThis(index)


def test_layout(widget: TERuleQueryTab) -> None:
    """Test the layout of the criteria frame."""
    rt, src, dst, tclass, perms, dflt, bools = widget.criteria

    assert widget.criteria_frame_layout.columnCount() == 2
    assert widget.criteria_frame_layout.rowCount() == 5
    assert widget.criteria_frame_layout.itemAtPosition(0, 0).widget() == rt
    assert widget.criteria_frame_layout.itemAtPosition(0, 1).widget() == rt
    assert widget.criteria_frame_layout.itemAtPosition(1, 0).widget() == src
    assert widget.criteria_frame_layout.itemAtPosition(1, 1).widget() == dst
    assert widget.criteria_frame_layout.itemAtPosition(2, 0).widget() == tclass
    assert widget.criteria_frame_layout.itemAtPosition(2, 1).widget() == perms
    assert widget.criteria_frame_layout.itemAtPosition(3, 0).widget() == dflt
    assert widget.criteria_frame_layout.itemAtPosition(3, 1).widget() == bools
    assert widget.criteria_frame_layout.itemAtPosition(4, 0).widget() == widget.buttonBox
    assert widget.criteria_frame_layout.itemAtPosition(4, 1).widget() == widget.buttonBox


def test_criteria_mapping(widget: TERuleQueryTab) -> None:
    """Test that widgets save to the correct query fields."""
    rt, src, dst, tclass, perms, dflt, bools = widget.criteria

    assert rt.attrname == "ruletype"
    assert src.attrname == "source"
    assert dst.attrname == "target"
    assert tclass.attrname == "tclass"
    assert perms.attrname == "perms"
    assert dflt.attrname == "default"
    assert bools.attrname == "boolean"
