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
