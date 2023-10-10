# SPDX-License-Identifier: GPL-2.0-only
from PyQt5 import QtCore
from pytestqt.qtbot import QtBot

from setoolsgui.widgets.criteria.boolean import (BooleanListCriteriaWidget,
                                                 BooleanNameCriteriaWidget)
from setoolsgui.widgets.models.table import SEToolsTableModel

from .util import _build_mock_query


def test_bool_list(qtbot: QtBot) -> None:
    """Test Boolean name list widget."""
    mock_query = _build_mock_query()
    widget = BooleanListCriteriaWidget("test_bool_list", mock_query, "name")
    qtbot.addWidget(widget)

    model = widget.criteria.model()
    assert isinstance(model, SEToolsTableModel)
    assert sorted(mock_query.policy.bools()) == model.item_list


def test_bool_name(qtbot: QtBot) -> None:
    """Test Boolean name line edit widget."""
    mock_query = _build_mock_query()
    widget = BooleanNameCriteriaWidget("test_bool_name", mock_query, "name")
    qtbot.addWidget(widget)

    model = widget.criteria.completer().model()
    assert isinstance(model, QtCore.QStringListModel)
    assert sorted(b.name for b in mock_query.policy.bools()) == model.stringList()
