# SPDX-License-Identifier: LGPL-2.1-only

import abc

from PyQt6 import QtCore

QObjectType: type = type(QtCore.QObject)


class MetaclassFix(QObjectType, abc.ABC):

    """
    Fix metaclass issues.

    Use this when doing a Generic[] with a PyQt type. Fixes this error:

    TypeError: metaclass conflict: the metaclass of a derived class must be a
    (non-strict) subclass of the metaclasses of all its bases
    """
    pass
