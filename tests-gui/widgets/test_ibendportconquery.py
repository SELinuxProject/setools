# SPDX-License-Identifier: GPL-2.0-only
import typing

from PyQt6 import QtWidgets
from pytestqt.qtbot import QtBot

import setools
from setoolsgui.widgets.ibendportconquery import IbendportconQueryTab
from setoolsgui.widgets import criteria, models

from .criteria.util import build_mock_policy


def test_docs(qtbot: QtBot) -> None:
    """Check that docs are provided for the widget."""
    mock_policy = build_mock_policy()
    widget = IbendportconQueryTab(mock_policy, None)
    qtbot.addWidget(widget)

    assert widget.whatsThis()
    assert widget.table_results.whatsThis()
    assert widget.raw_results.whatsThis()

    for w in widget.criteria:
        assert w.toolTip()
        assert w.whatsThis()

    results = typing.cast(QtWidgets.QTabWidget, widget.results)
    for index in range(results.count()):
        assert results.tabWhatsThis(index)


def test_layout(qtbot: QtBot) -> None:
    """Test the layout of the criteria frame."""
    mock_policy = build_mock_policy()
    widget = IbendportconQueryTab(mock_policy, None)
    qtbot.addWidget(widget)

    name, port, context = widget.criteria

    assert widget.criteria_frame_layout.columnCount() == 4
    assert widget.criteria_frame_layout.rowCount() == 3
    assert widget.criteria_frame_layout.itemAtPosition(0, 0).widget() == name
    assert widget.criteria_frame_layout.itemAtPosition(0, 1).widget() == name
    assert widget.criteria_frame_layout.itemAtPosition(0, 2).widget() == port
    assert widget.criteria_frame_layout.itemAtPosition(0, 3).widget() == port
    assert widget.criteria_frame_layout.itemAtPosition(1, 0).widget() == context
    assert widget.criteria_frame_layout.itemAtPosition(1, 1).widget() == context
    assert widget.criteria_frame_layout.itemAtPosition(1, 2).widget() == context
    assert widget.criteria_frame_layout.itemAtPosition(1, 3).widget() == context
    assert widget.criteria_frame_layout.itemAtPosition(2, 0).widget() == widget.buttonBox
    assert widget.criteria_frame_layout.itemAtPosition(2, 1).widget() == widget.buttonBox
    assert widget.criteria_frame_layout.itemAtPosition(2, 2).widget() == widget.buttonBox
    assert widget.criteria_frame_layout.itemAtPosition(2, 3).widget() == widget.buttonBox


def test_criteria_mapping(qtbot: QtBot) -> None:
    """Test that widgets save to the correct query fields."""
    mock_policy = build_mock_policy()
    widget = IbendportconQueryTab(mock_policy, None)
    qtbot.addWidget(widget)

    name, port, context = widget.criteria
    context = typing.cast(criteria.ContextMatch, context)

    assert isinstance(widget.query, setools.IbendportconQuery)
    assert isinstance(widget.table_results_model, models.IbendportconTable)
    assert name.attrname == "name"
    assert port.attrname == "port"
    assert context.user_attrname == "user"
    assert context.role_attrname == "role"
    assert context.type_attrname == "type_"
    assert context.range_attrname == "range_"
