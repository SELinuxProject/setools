# SPDX-License-Identifier: LGPL-2.1-only

from PyQt6 import QtCore, QtWidgets
import setools

from .criteria import OptionsPlacement
from .name import NameWidget

# Regex for exact matches to roles
VALIDATE_EXACT = r"[A-Za-z0-9._-]*"

__all__ = ("UserName",)


class UserName(NameWidget):

    """
    Widget providing a QLineEdit that saves the input to the attributes
    of the specified query.  This supports inputs of users.
    """

    indirect_toggled = QtCore.pyqtSignal(bool)

    def __init__(self, title: str, query: setools.PolicyQuery, attrname: str, /, *,
                 parent: QtWidgets.QWidget | None = None,
                 options_placement: OptionsPlacement = OptionsPlacement.RIGHT,
                 required: bool = False, enable_regex: bool = True):

        # Create completion list
        completion = list[str](u.name for u in query.policy.users())

        super().__init__(title, query, attrname, completion, VALIDATE_EXACT,
                         enable_regex=enable_regex, required=required,
                         options_placement=options_placement, parent=parent)


if __name__ == '__main__':
    import sys
    import logging
    import warnings

    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s|%(levelname)s|%(name)s|%(message)s')
    warnings.simplefilter("default")

    q = setools.PortconQuery(setools.SELinuxPolicy())

    app = QtWidgets.QApplication(sys.argv)
    mw = QtWidgets.QMainWindow()
    widget = UserName("Test user", q, "user", parent=mw)
    widget.setToolTip("test tooltip")
    widget.setWhatsThis("test whats this")
    mw.setCentralWidget(widget)
    mw.resize(widget.size())
    whatsthis = QtWidgets.QWhatsThis.createAction(mw)
    mw.menuBar().addAction(whatsthis)  # type: ignore[union-attr]
    mw.setStatusBar(QtWidgets.QStatusBar(mw))
    mw.show()
    sys.exit(app.exec())
