# SPDX-License-Identifier: LGPL-2.1-only
from itertools import chain
from typing import TYPE_CHECKING

from PyQt5 import QtCore, QtGui, QtWidgets
from setools.exception import NoCommon

from .util import display_object_details

if TYPE_CHECKING:
    from typing import Optional
    from setools import Boolean


def boolean_detail(boolean: "Boolean", parent: "Optional[QtWidgets.QWidget]" = None) -> None:
    """Display a dialog with Boolean details."""

    display_object_details(
        f"{boolean} Details",
        f"""
        <h1>Boolean Name</h1>
        <p>{boolean}<p>

        <p><b>Default state: {boolean.state}</b></p>
        """,
        parent)


def boolean_detail_action(boolean: "Boolean",
                          parent: "Optional[QtWidgets.QWidget]" = None) -> QtWidgets.QAction:
    """Return a QAction that, when triggered, opens a Boolean detail popup."""
    a = QtWidgets.QAction(f"Properties of {boolean}")
    a.triggered.connect(lambda x: boolean_detail(boolean, parent))
    return a


def boolean_tooltip(boolean: "Boolean") -> str:
    """Return tooltip text for this Boolean."""
    return f"{boolean} is a Boolean with {boolean.state} default state."
