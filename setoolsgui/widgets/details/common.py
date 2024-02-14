# SPDX-License-Identifier: LGPL-2.1-only
from PyQt6 import QtGui, QtWidgets
import setools

from . import util

__all__ = ('common_detail', 'common_detail_action', 'common_tooltip')


def common_detail(common: setools.Common, parent: QtWidgets.QWidget | None = None) -> None:
    """Display a dialog with common details."""

    util.display_object_details(
        f"{common} Details",
        f"""
        <h1>Common Name</h1>
        <p>{common}<p>

        <h2>Permissions ({len(common.perms)})</h2>
        <ul>
        {"".join(f"<li>{p}</li>" for p in sorted(common.perms))}
        </ul>
        """,
        parent)


def common_detail_action(common: setools.Common,
                         parent: QtWidgets.QWidget | None = None) -> QtGui.QAction:
    """Return a QAction that, when triggered, opens a common detail popup."""
    a = QtGui.QAction(f"Properties of {common}")
    a.triggered.connect(lambda x: common_detail(common, parent))
    return a


def common_tooltip(common: setools.Common) -> str:
    """Return tooltip text for this common."""
    nperms = len(common.perms)
    if nperms == 0:
        return f"{common} is a common permission set with no permissions defined."
    elif nperms > 5:
        return f"{common} is a common permission set with {nperms} permissions defined."
    else:
        return f"{common} is a common permission set with permissions: " \
                f"{', '.join(common.perms)}"
