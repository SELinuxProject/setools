# SPDX-License-Identifier: LGPL-2.1-only

from PyQt6 import QtGui, QtWidgets
import setools

from . import util

__all__ = ('typeattr_detail', 'typeattr_detail_action', 'typeattr_tooltip')


def typeattr_detail(attr: setools.TypeAttribute, parent: QtWidgets.QWidget | None = None) -> None:

    """Display a dialog with type attribute details."""

    types = list[setools.Type](sorted(attr.expand()))

    util.display_object_details(
        f"{attr} Details",
        f"""
        <h1>Type Attribute Name</h1>
        <p>{attr}<p>

        <h2>Types ({len(types)})</h2>
        <ul>
        {"".join(f"<li>{t}</li>" for t in types)}
        </ul>
        """,
        parent)


def typeattr_detail_action(attr: setools.TypeAttribute,
                           parent: QtWidgets.QWidget | None = None) -> QtGui.QAction:

    """Return a QAction that, when triggered, opens an detail popup for the attr."""

    a = QtGui.QAction(f"Properties of {attr}")
    a.triggered.connect(lambda _: typeattr_detail(attr, parent))
    return a


def typeattr_tooltip(attr: setools.TypeAttribute) -> str:
    """Return tooltip text for this type attribute."""
    n_types = len(attr)
    if n_types == 0:
        return f"{attr.name} is an empty attribute."
    elif n_types > 5:
        return f"{attr.name} is an attribute consisting of {n_types} types."
    else:
        return f"{attr.name} is an attribute consisting of: " \
                f"{', '.join(t.name for t in attr.expand())}"
