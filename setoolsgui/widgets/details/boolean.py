# SPDX-License-Identifier: LGPL-2.1-only

from PyQt6 import QtGui, QtWidgets
import setools

from . import util

__all__ = ('boolean_detail', 'boolean_detail_action', 'boolean_tooltip')


def boolean_detail(boolean: setools.Boolean, parent: QtWidgets.QWidget | None = None) -> None:
    """Display a dialog with Boolean details."""

    util.display_object_details(
        f"{boolean} Details",
        f"""
        <h1>Boolean Name</h1>
        <p>{boolean}<p>

        <p><b>Default state: {boolean.state}</b></p>
        """,
        parent)


def boolean_detail_action(boolean: setools.Boolean,
                          parent: QtWidgets.QWidget | None = None) -> QtGui.QAction:
    """Return a QAction that, when triggered, opens a Boolean detail popup."""
    a = QtGui.QAction(f"Properties of {boolean}")
    a.triggered.connect(lambda x: boolean_detail(boolean, parent))
    return a


def boolean_tooltip(boolean: setools.Boolean) -> str:
    """Return tooltip text for this Boolean."""
    return f"{boolean} is a Boolean with {boolean.state} default state."
