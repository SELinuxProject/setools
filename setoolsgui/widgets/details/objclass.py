# SPDX-License-Identifier: LGPL-2.1-only
from itertools import chain
from typing import TYPE_CHECKING

from PyQt5 import QtCore, QtGui, QtWidgets
from setools.exception import NoCommon

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
            <h2>Permissions inherited  from {common} ({len(common.perms)})</h2>
            <ul>
            {"".join(f"<li>{p}</li>" for p in sorted(common.perms))}
            </ul>
            """

    except NoCommon:
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


def objclass_detail_action(class_: "ObjClass",
                           parent: "Optional[QtWidgets.QWidget]" = None) -> QtWidgets.QAction:
    """Return a QAction that, when triggered, opens an object class detail popup."""
    a = QtWidgets.QAction(f"Properties of {class_}")
    a.triggered.connect(lambda x: objclass_detail(class_, parent))
    return a


def objclass_tooltip(class_: "ObjClass") -> str:
    """Return tooltip text for this object class."""
    try:
        nperms = len(class_.perms) + len(class_.common.perms)
        if nperms == 0:
            return f"{class_} is an object class with no permissions defined."
        elif nperms > 5:
            return \
                f"{class_} inherits {class_.common} and consists of " \
                f"{nperms} permissions."
        else:
            return f"{class_.name} is an object class with permissions: " \
                   f"{', '.join(chain(class_.common.perms, class_.perms))}"

    except NoCommon:
        nperms = len(class_.perms)
        if nperms == 0:
            return f"{class_} is an object class with no permissions defined."
        elif nperms > 5:
            return f"{class_} is an object class with {nperms} permissions defined."
        else:
            return f"{class_} is an object class with permissions: " \
                    f"{', '.join(class_.perms)}"
