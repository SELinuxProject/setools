# SPDX-License-Identifier: LGPL-2.1-only
import enum


from PyQt6 import QtCore

__all__ = ("ModelRoles",)


class ModelRoles(enum.IntEnum):

    """
    Roles for SETools models.

    The intent is to be a superset of QtCore.Qt.ItemDataRole, with
    additional custom roles for SETools models.

    https://doc.qt.io/qt-6/qt.html#ItemDataRole-enum
    """

    # general purpose roles
    DisplayRole = QtCore.Qt.ItemDataRole.DisplayRole
    DecorationRole = QtCore.Qt.ItemDataRole.DecorationRole
    EditRole = QtCore.Qt.ItemDataRole.EditRole
    ToolTipRole = QtCore.Qt.ItemDataRole.ToolTipRole
    StatusTipRole = QtCore.Qt.ItemDataRole.StatusTipRole
    WhatsThisRole = QtCore.Qt.ItemDataRole.WhatsThisRole
    SizeHintRole = QtCore.Qt.ItemDataRole.SizeHintRole

    # appearance/metadata roles
    FontRole = QtCore.Qt.ItemDataRole.FontRole
    TextAlignmentRole = QtCore.Qt.ItemDataRole.TextAlignmentRole
    BackgroundRole = QtCore.Qt.ItemDataRole.BackgroundRole
    ForegroundRole = QtCore.Qt.ItemDataRole.ForegroundRole
    CheckStateRole = QtCore.Qt.ItemDataRole.CheckStateRole
    InitialSortOrderRole = QtCore.Qt.ItemDataRole.UserRole

    # accessibility roles
    AccessibleTextRole = QtCore.Qt.ItemDataRole.AccessibleTextRole
    AccessibleDescriptionRole = QtCore.Qt.ItemDataRole.AccessibleDescriptionRole

    # Custom roles
    PolicyObjRole = QtCore.Qt.ItemDataRole.UserRole
    ContextMenuRole = QtCore.Qt.ItemDataRole.UserRole + 1
