# SPDX-License-Identifier: GPL-2.0-only
from typing import cast

from PyQt6 import QtWidgets
from pytestqt.qtbot import QtBot

from setoolsgui.widgets.mlsrulequery import MLSRuleQueryTab

from .criteria.util import build_mock_policy


def test_docs(qtbot: QtBot) -> None:
    """Check that docs are provided for the widget."""
    mock_policy = build_mock_policy()
    widget = MLSRuleQueryTab(mock_policy, None)
    qtbot.addWidget(widget)

    assert widget.whatsThis()
    assert widget.table_results.whatsThis()
    assert widget.raw_results.whatsThis()

    for w in widget.criteria:
        assert w.toolTip()
        assert w.whatsThis()

    results = cast(QtWidgets.QTabWidget, widget.results)
    for index in range(results.count()):
        assert results.tabWhatsThis(index)


def test_layout(qtbot: QtBot) -> None:
    """Test the layout of the criteria frame."""
    mock_policy = build_mock_policy()
    widget = MLSRuleQueryTab(mock_policy, None)
    qtbot.addWidget(widget)

    rt, src, dst, tclass, dflt = widget.criteria

    assert widget.criteria_frame_layout.columnCount() == 2
    assert widget.criteria_frame_layout.rowCount() == 4
    assert widget.criteria_frame_layout.itemAtPosition(0, 0).widget() == rt
    assert widget.criteria_frame_layout.itemAtPosition(0, 1).widget() == rt
    assert widget.criteria_frame_layout.itemAtPosition(1, 0).widget() == src
    assert widget.criteria_frame_layout.itemAtPosition(1, 1).widget() == dst
    assert widget.criteria_frame_layout.itemAtPosition(2, 0).widget() == tclass
    assert widget.criteria_frame_layout.itemAtPosition(2, 1).widget() == dflt
    assert widget.criteria_frame_layout.itemAtPosition(3, 0).widget() == widget.buttonBox
    assert widget.criteria_frame_layout.itemAtPosition(3, 1).widget() == widget.buttonBox


def test_criteria_mapping(qtbot: QtBot) -> None:
    """Test that widgets save to the correct query fields."""
    mock_policy = build_mock_policy()
    widget = MLSRuleQueryTab(mock_policy, None)
    qtbot.addWidget(widget)

    rt, src, dst, tclass, dflt = widget.criteria

    assert rt.attrname == "ruletype"
    assert src.attrname == "source"
    assert dst.attrname == "target"
    assert tclass.attrname == "tclass"
    assert dflt.attrname == "default"
