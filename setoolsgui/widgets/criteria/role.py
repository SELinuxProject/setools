# SPDX-License-Identifier: LGPL-2.1-only

from PyQt5 import QtCore, QtWidgets
import setools

from .criteria import OptionsPlacement
from .name import NameCriteriaWidget

# Regex for exact matches to roles
VALIDATE_EXACT = r"[A-Za-z0-9._-]*"

__all__ = ("RoleNameWidget",)


class RoleNameWidget(NameCriteriaWidget):

    """
    Widget providing a QLineEdit that saves the input to the attributes
    of the specified query.  This supports inputs of roles.
    """

    indirect_toggled = QtCore.pyqtSignal(bool)

    def __init__(self, title: str, query: setools.PolicyQuery, attrname: str, /, *,
                 parent: QtWidgets.QWidget | None = None,
                 options_placement: OptionsPlacement = OptionsPlacement.RIGHT,
                 required: bool = False, enable_regex: bool = True):

        # Create completion list
        completion = list[str](r.name for r in query.policy.roles())

        super().__init__(title, query, attrname, completion, VALIDATE_EXACT,
                         enable_regex=enable_regex, required=required, parent=parent,
                         options_placement=options_placement)


if __name__ == '__main__':
    import sys
    import logging
    import warnings

    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s|%(levelname)s|%(name)s|%(message)s')
    warnings.simplefilter("default")

    q = setools.RBACRuleQuery(setools.SELinuxPolicy())

    app = QtWidgets.QApplication(sys.argv)
    mw = QtWidgets.QMainWindow()
    widget = RoleNameWidget("Test Role", q, "source", parent=mw)
    widget.setToolTip("test tooltip")
    widget.setWhatsThis("test whats this")
    mw.setCentralWidget(widget)
    mw.resize(widget.size())
    whatsthis = QtWidgets.QWhatsThis.createAction(mw)
    mw.menuBar().addAction(whatsthis)  # type: ignore[union-attr]
    mw.setStatusBar(QtWidgets.QStatusBar(mw))
    mw.show()
    sys.exit(app.exec_())
