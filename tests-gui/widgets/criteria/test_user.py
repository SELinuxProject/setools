# SPDX-License-Identifier: GPL-2.0-only

from PyQt5 import QtCore
from pytestqt.qtbot import QtBot

from setoolsgui.widgets.criteria import UserNameWidget

from .util import build_mock_query


def test_base_settings(qtbot: QtBot) -> None:
    mock_query = build_mock_query()
    widget = UserNameWidget("test_base_settings", mock_query, "name")
    qtbot.addWidget(widget)

    model = widget.criteria.completer().model()
    assert isinstance(model, QtCore.QStringListModel)
    assert sorted(r.name for r in mock_query.policy.users()) == model.stringList()
