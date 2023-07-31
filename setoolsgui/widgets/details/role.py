# SPDX-License-Identifier: LGPL-2.1-only
from typing import TYPE_CHECKING

from PyQt5 import QtCore, QtGui, QtWidgets

from .util import display_object_details

if TYPE_CHECKING:
    from typing import List, Optional
    from setools.policyrep import Role, Type


def role_detail(role: "Role", parent: "Optional[QtWidgets.QWidget]" = None) -> None:

    """Display a dialog with role details."""

    types: "List[Type]" = sorted(role.types())

    display_object_details(
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


def role_detail_action(role: "Role",
                       parent: "Optional[QtWidgets.QWidget]" = None) -> QtWidgets.QAction:

    """Return a QAction that, when triggered, opens an detail popup for role."""

    a = QtWidgets.QAction(f"Properties of {role}")
    a.triggered.connect(lambda x: role_detail(role, parent))
    return a


def role_tooltip(role: "Role") -> str:
    """Return tooltip text for this role."""
    n_types = len(list(role.types()))
    if n_types == 0:
        return f"{role} is a role with no type associations."
    elif n_types > 5:
        return f"{role} is a role associated with {n_types} types."
    else:
        return f"{role} is a role associated with types: " \
                f"{', '.join(t.name for t in role.expand())}"
