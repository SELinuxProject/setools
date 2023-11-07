# SPDX-License-Identifier: LGPL-2.1-only

from PyQt6 import QtGui, QtWidgets
import setools

from . import util

__all__ = ("user_detail", "user_detail_action", "user_tooltip")


def user_detail(user: setools.User, parent: QtWidgets.QWidget | None = None) -> None:

    """Display a dialog with user details."""

    roles = list[setools.Role](sorted(user.roles))

    try:
        mlsinfo = f"""
                  <h2>MLS Default Level</h2>
                  <p>{user.mls_level}</p>

                  <h2>MLS Range</h2>
                  <p>{user.mls_range}</p>
                  """

    except setools.exception.MLSDisabled:
        mlsinfo = ""

    util.display_object_details(
        f"{user} Details",
        f"""
        <h1>User Name</h1>
        <p>{user}<p>

        <h2>Roles ({len(roles)})</h2>
        <ul>
        {"".join(f"<li>{t}</li>" for t in roles)}
        </ul>
        {mlsinfo}
        """,
        parent)


def user_detail_action(user: setools.User,
                       parent: QtWidgets.QWidget | None = None) -> QtGui.QAction:

    """Return a QAction that, when triggered, opens an detail popup for user."""

    a = QtGui.QAction(f"Properties of {user}")
    a.triggered.connect(lambda x: user_detail(user, parent))
    return a


def user_tooltip(user: setools.User) -> str:
    """Return tooltip text for this user."""
    n_roles = len(user.roles)
    if n_roles == 0:
        return f"{user} is a user with no type associations."
    elif n_roles > 5:
        return f"{user} is a user associated with {n_roles} types."
    else:
        return f"{user} is a user associated with types: " \
                f"{', '.join(r.name for r in user.roles)}"
