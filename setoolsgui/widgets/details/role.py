# SPDX-License-Identifier: LGPL-2.1-only

from PyQt6 import QtGui, QtWidgets
import setools

from . import util

__all__ = ("role_detail", "role_detail_action", "role_tooltip")


def role_detail(role: setools.Role, parent: QtWidgets.QWidget | None = None) -> None:

    """Display a dialog with role details."""

    types = list[setools.Type](sorted(role.types()))

    util.display_object_details(
        f"{role} Details",
        f"""
        <h1>Role Name</h1>
        <p>{role}<p>

        <h2>Types ({len(types)})</h2>
        <ul>
        {"".join(f"<li>{t}</li>" for t in types)}
        </ul>
        """,
        parent)


def role_detail_action(role: setools.Role,
                       parent: QtWidgets.QWidget | None = None) -> QtGui.QAction:

    """Return a QAction that, when triggered, opens an detail popup for role."""

    a = QtGui.QAction(f"Properties of {role}")
    a.triggered.connect(lambda x: role_detail(role, parent))
    return a


def role_tooltip(role: setools.Role) -> str:
    """Return tooltip text for this role."""
    n_types = len(list(role.types()))
    if n_types == 0:
        return f"{role} is a role with no type associations."
    elif n_types > 5:
        return f"{role} is a role associated with {n_types} types."
    else:
        return f"{role} is a role associated with types: " \
                f"{', '.join(t.name for t in role.types())}"
