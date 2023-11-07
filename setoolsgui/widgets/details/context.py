# SPDX-License-Identifier: LGPL-2.1-only

from PyQt6 import QtGui, QtWidgets
import setools

from .role import role_detail_action
from .type import type_detail_action
from .user import user_detail_action

__all__ = ("context_detail_action",)


def context_detail_action(context: setools.Context,
                          parent: QtWidgets.QWidget | None = None) -> tuple[QtGui.QAction,
                                                                            QtGui.QAction,
                                                                            QtGui.QAction]:

    """Return a tuple of QActions that, when triggered, opens a detail popup for the context."""
    return (user_detail_action(context.user, parent),
            role_detail_action(context.role, parent),
            type_detail_action(context.type_, parent))
