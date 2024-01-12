# SPDX-License-Identifier: GPL-2.0-only
import typing

from PyQt6 import QtWidgets
import pytest
from pytestqt.qtbot import QtBot

import setools
from setoolsgui.widgets import criteria
from setoolsgui.widgets.defaultquery import DefaultQueryTab


@pytest.fixture
def widget(mock_policy, request: pytest.FixtureRequest, qtbot: QtBot) -> DefaultQueryTab:
    """Pytest fixture to set up the widget."""
    marker = request.node.get_closest_marker("obj_args")
    kwargs = marker.kwargs if marker else {}
    w = DefaultQueryTab(mock_policy, **kwargs)
    qtbot.addWidget(w)
    w.show()
    return w


def test_docs(widget: DefaultQueryTab) -> None:
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


def test_layout(widget: DefaultQueryTab) -> None:
    """Test the layout of the criteria frame."""
    rt, tclass, dfl = widget.criteria

    assert widget.criteria_frame_layout.columnCount() == 2
    assert widget.criteria_frame_layout.rowCount() == 3
    assert widget.criteria_frame_layout.itemAtPosition(0, 0).widget() == rt
    assert widget.criteria_frame_layout.itemAtPosition(0, 1).widget() == tclass
    assert widget.criteria_frame_layout.itemAtPosition(1, 0).widget() == dfl
    assert widget.criteria_frame_layout.itemAtPosition(1, 1) is None
    assert widget.criteria_frame_layout.itemAtPosition(2, 0).widget() == widget.buttonBox
    assert widget.criteria_frame_layout.itemAtPosition(2, 1).widget() == widget.buttonBox


def test_criteria_mapping(widget: DefaultQueryTab) -> None:
    """Test that widgets save to the correct query fields."""
    rt, tclass, dfl = widget.criteria

    assert isinstance(widget.query, setools.DefaultQuery)
    assert rt.attrname == "ruletype"
    assert tclass.attrname == "tclass"
    assert dfl.attrname == "default"
    assert isinstance(dfl, criteria.DefaultValues)
    assert dfl.range_attrname == "default_range"
