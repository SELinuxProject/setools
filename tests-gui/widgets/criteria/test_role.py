# SPDX-License-Identifier: GPL-2.0-only
from typing import Dict, Union

from PyQt5 import QtCore
from pytestqt.qtbot import QtBot

from setoolsgui.widgets.criteria.role import RoleNameWidget

from .util import _build_mock_query


def test_base_settings(qtbot: QtBot) -> None:
    mock_query = _build_mock_query()
    widget = RoleNameWidget("test_base_settings", mock_query, "name")
    qtbot.addWidget(widget)

    model = widget.criteria.completer().model()
    assert isinstance(model, QtCore.QStringListModel)
    assert sorted(r.name for r in mock_query.policy.roles()) == model.stringList()