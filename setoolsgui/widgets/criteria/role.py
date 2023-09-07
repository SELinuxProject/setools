# SPDX-License-Identifier: LGPL-2.1-only

from typing import TYPE_CHECKING

from PyQt5 import QtCore, QtWidgets

from .name import NameCriteriaWidget

if TYPE_CHECKING:
    from typing import List, Optional

# Regex for exact matches to types/attrs
VALIDATE_EXACT = r"[A-Za-z0-9._-]*"


class RoleNameWidget(NameCriteriaWidget):

    """
    Widget providing a QLineEdit that saves the input to the attributes
    of the specified query.  This supports inputs of roles.
    """

    indirect_toggled = QtCore.pyqtSignal(bool)

    def __init__(self, title: str, query, attrname: str,
                 parent: "Optional[QtWidgets.QWidget]" = None,
                 required: bool = False, enable_regex: bool = True):

        # Create completion list
        completion: "List[str]" = [r.name for r in query.policy.roles()]

        super().__init__(title, query, attrname, completion, VALIDATE_EXACT,
                         enable_regex=enable_regex, required=required, parent=parent)


if __name__ == '__main__':
    import sys
    import logging
    import warnings
    import setools

    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s|%(levelname)s|%(name)s|%(message)s')
    warnings.simplefilter("default")

    q = setools.RBACRuleQuery(setools.SELinuxPolicy())

    app = QtWidgets.QApplication(sys.argv)
    mw = QtWidgets.QMainWindow()
    widget = RoleNameWidget("Test Role", q, "source", mw)
    widget.setToolTip("test tooltip")
    widget.setWhatsThis("test whats this")
    mw.setCentralWidget(widget)
    mw.resize(widget.size())
    whatsthis = QtWidgets.QWhatsThis.createAction(mw)
    mw.menuBar().addAction(whatsthis)
    mw.setStatusBar(QtWidgets.QStatusBar(mw))
    mw.show()
    sys.exit(app.exec_())
