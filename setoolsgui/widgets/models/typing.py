# SPDX-License-Identifier: LGPL-2.1-only

import abc

from PyQt6 import QtCore, QtGui

# These are all of the return types for the standard QtCore.Qt.ItemDataRole roles
# for the data method in the models.
AllStdDataTypes = str | QtGui.QColor | QtGui.QIcon | QtGui.QPixmap | QtCore.QSize | \
    QtGui.QFont | QtCore.Qt.AlignmentFlag | QtGui.QBrush | QtCore.Qt.CheckState | \
    QtCore.Qt.SortOrder | None

# This is the return type for the ModelRoles.ContextMenuRole role
ContextMenuType = tuple[QtGui.QAction, ...]


class MetaclassFix(type(QtCore.QObject), abc.ABC):  # type: ignore[misc]

    """
    Fix metaclass issues.

    Use this when doing a Generic[] with a PyQt type. Fixes this error:

    TypeError: metaclass conflict: the metaclass of a derived class must be a
    (non-strict) subclass of the metaclasses of all its bases
    """
    pass
