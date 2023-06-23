# SPDX-License-Identifier: GPL-2.0-only
from PyQt5 import QtCore, QtGui, QtWidgets
from pytestqt.qtbot import QtBot

from setools import TERuletype

from setoolsgui.widgets.criteria.teruletype import TERuleTypeCriteriaWidget

from .util import _build_mock_query


def test_base_settings(qtbot: QtBot) -> None:
    """Test base properties of widget."""
    mock_query = _build_mock_query()
    widget = TERuleTypeCriteriaWidget("title", mock_query, "checkboxes")
    qtbot.addWidget(widget)

    assert len(widget.criteria) == len(TERuletype)
    assert not widget.criteria["neverallow"].isEnabled()
    assert not widget.criteria["neverallowxperm"].isEnabled()
