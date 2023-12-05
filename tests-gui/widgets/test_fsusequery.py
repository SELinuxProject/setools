# SPDX-License-Identifier: GPL-2.0-only
import typing

from PyQt6 import QtWidgets
import pytest
from pytestqt.qtbot import QtBot

import setools
from setoolsgui.widgets.fsusequery import FSUseQueryTab
from setoolsgui.widgets import criteria, models


@pytest.fixture
def widget(mock_policy, request: pytest.FixtureRequest, qtbot: QtBot) -> FSUseQueryTab:
    """Pytest fixture to set up the widget."""
    marker = request.node.get_closest_marker("obj_args")
    kwargs = marker.kwargs if marker else {}
    w = FSUseQueryTab(mock_policy, **kwargs)
    qtbot.addWidget(w)
    w.show()
    return w


def test_docs(widget: FSUseQueryTab) -> None:
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


def test_layout(widget: FSUseQueryTab) -> None:
    """Test the layout of the criteria frame."""
    ruletype, fs, context = widget.criteria

    assert widget.criteria_frame_layout.columnCount() == 4
    assert widget.criteria_frame_layout.rowCount() == 3
    assert widget.criteria_frame_layout.itemAtPosition(0, 0).widget() == ruletype
    assert widget.criteria_frame_layout.itemAtPosition(0, 1).widget() == ruletype
    assert widget.criteria_frame_layout.itemAtPosition(0, 2).widget() == fs
    assert widget.criteria_frame_layout.itemAtPosition(0, 3).widget() == fs
    assert widget.criteria_frame_layout.itemAtPosition(1, 0).widget() == context
    assert widget.criteria_frame_layout.itemAtPosition(1, 1).widget() == context
    assert widget.criteria_frame_layout.itemAtPosition(1, 2).widget() == context
    assert widget.criteria_frame_layout.itemAtPosition(1, 3).widget() == context
    assert widget.criteria_frame_layout.itemAtPosition(2, 0).widget() == widget.buttonBox
    assert widget.criteria_frame_layout.itemAtPosition(2, 1).widget() == widget.buttonBox
    assert widget.criteria_frame_layout.itemAtPosition(2, 2).widget() == widget.buttonBox
    assert widget.criteria_frame_layout.itemAtPosition(2, 3).widget() == widget.buttonBox


def test_criteria_mapping(widget: FSUseQueryTab) -> None:
    """Test that widgets save to the correct query fields."""
    ruletype, fs, context = widget.criteria
    context = typing.cast(criteria.ContextMatch, context)

    assert isinstance(widget.query, setools.FSUseQuery)
    assert isinstance(widget.table_results_model, models.FSUseTable)
    assert ruletype.attrname == "ruletype"
    assert fs.attrname == "fs"
    assert context.user_attrname == "user"
    assert context.role_attrname == "role"
    assert context.type_attrname == "type_"
    assert context.range_attrname == "range_"
