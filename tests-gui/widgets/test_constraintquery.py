# SPDX-License-Identifier: GPL-2.0-only
import typing

from PyQt6 import QtWidgets
import pytest
from pytestqt.qtbot import QtBot

import setools
from setoolsgui.widgets.constraintquery import ConstraintQueryTab
from setoolsgui.widgets import models


@pytest.fixture
def widget(mock_policy, request: pytest.FixtureRequest, qtbot: QtBot) -> ConstraintQueryTab:
    """Pytest fixture to set up the widget."""
    marker = request.node.get_closest_marker("obj_args")
    kwargs = marker.kwargs if marker else {}
    w = ConstraintQueryTab(mock_policy, **kwargs)
    qtbot.addWidget(w)
    w.show()
    return w


def test_docs(widget: ConstraintQueryTab) -> None:
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


def test_layout(widget: ConstraintQueryTab) -> None:
    """Test the layout of the criteria frame."""
    rt, user, role, type_, tclass, perms = widget.criteria

    assert widget.criteria_frame_layout.columnCount() == 2
    assert widget.criteria_frame_layout.rowCount() == 4
    assert widget.criteria_frame_layout.itemAtPosition(0, 0).widget() == rt
    assert widget.criteria_frame_layout.itemAtPosition(0, 1).widget() == user
    assert widget.criteria_frame_layout.itemAtPosition(1, 0).widget() == role
    assert widget.criteria_frame_layout.itemAtPosition(1, 1).widget() == type_
    assert widget.criteria_frame_layout.itemAtPosition(2, 0).widget() == tclass
    assert widget.criteria_frame_layout.itemAtPosition(2, 1).widget() == perms
    assert widget.criteria_frame_layout.itemAtPosition(3, 0).widget() == widget.buttonBox
    assert widget.criteria_frame_layout.itemAtPosition(3, 1).widget() == widget.buttonBox


def test_criteria_mapping(widget: ConstraintQueryTab) -> None:
    """Test that widgets save to the correct query fields."""
    rt, user, role, type_, tclass, perms = widget.criteria

    assert isinstance(widget.query, setools.ConstraintQuery)
    assert isinstance(widget.table_results_model, models.ConstraintTable)
    assert rt.attrname == "ruletype"
    assert user.attrname == "user"
    assert role.attrname == "role"
    assert type_.attrname == "type_"
    assert tclass.attrname == "tclass"
    assert perms.attrname == "perms"
