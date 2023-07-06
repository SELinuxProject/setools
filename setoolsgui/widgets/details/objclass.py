# SPDX-License-Identifier: LGPL-2.1-only
from typing import TYPE_CHECKING

from PyQt5 import QtCore, QtGui, QtWidgets

from .util import display_object_details

if TYPE_CHECKING:
    from typing import Optional
    from setools.policyrep import ObjClass


def objclass_detail(class_: "ObjClass", parent: "Optional[QtWidgets.QWidget]" = None) -> None:

    """Display a dialog with object class details."""

    try:
        common = class_.common
        common_details = \
            f"""
            <h2>{common} Common Permissions ({len(common.perms)})</h2>
            <ul>
            {"".join(f"<li>{p}</li>" for p in sorted(common.perms))}
            </ul>
            """

    except Exception:
        common_details = ""

    display_object_details(
        f"{class_} Details",
        f"""
        <h1>Object Class Name</h1>
        <p>{class_}<p>

        {common_details}

        <h2>Permissions ({len(class_.perms)})</h2>
        <ul>
        {"".join(f"<li>{p}</li>" for p in sorted(class_.perms))}
        </ul>
        """,
        parent)
