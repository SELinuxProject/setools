# SPDX-License-Identifier: LGPL-2.1-only
from itertools import chain

from PyQt6 import QtGui, QtWidgets
import setools

from . import util

__all__ = ('objclass_detail', 'objclass_detail_action', 'objclass_tooltip')


def objclass_detail(class_: setools.ObjClass, parent: QtWidgets.QWidget | None = None) -> None:
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

    except setools.exception.NoCommon:
        common_details = ""

    util.display_object_details(
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


def objclass_detail_action(class_: setools.ObjClass,
                           parent: QtWidgets.QWidget | None = None) -> QtGui.QAction:
    """Return a QAction that, when triggered, opens an object class detail popup."""
    a = QtGui.QAction(f"Properties of {class_}")
    a.triggered.connect(lambda x: objclass_detail(class_, parent))
    return a


def objclass_tooltip(class_: setools.ObjClass) -> str:
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

    except setools.exception.NoCommon:
        nperms = len(class_.perms)
        if nperms == 0:
            return f"{class_} is an object class with no permissions defined."
        elif nperms > 5:
            return f"{class_} is an object class with {nperms} permissions defined."
        else:
            return f"{class_} is an object class with permissions: " \
                    f"{', '.join(class_.perms)}"
