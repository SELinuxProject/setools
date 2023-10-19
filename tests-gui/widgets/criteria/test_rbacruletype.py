# SPDX-License-Identifier: GPL-2.0-only
from pytestqt.qtbot import QtBot

from setools import RBACRuletype

from setoolsgui.widgets.criteria.rbacruletype import RBACRuleTypeCriteriaWidget

from .util import build_mock_query


def test_base_settings(qtbot: QtBot) -> None:
    """Test base properties of widget."""
    mock_query = build_mock_query()
    widget = RBACRuleTypeCriteriaWidget("title", mock_query, "checkboxes")
    qtbot.addWidget(widget)

    assert len(widget.criteria) == len(RBACRuletype)
