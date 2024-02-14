# SPDX-License-Identifier: LGPL-2.1-only

from PyQt6 import QtCore, QtWidgets
import setools

from .. import models
from .criteria import OptionsPlacement
from .list import ListWidget
from .name import NameWidget

# Regex for exact matches to roles
VALIDATE_EXACT = r"[A-Za-z0-9._-]*"

__all__ = ("RoleList", "RoleName",)


class RoleList(ListWidget):

    """A widget providing a QListView widget for selecting the roles."""

    def __init__(self, title: str, query: setools.PolicyQuery, attrname: str,
                 enable_equal: bool = False, enable_subset: bool = False,
                 parent: QtWidgets.QWidget | None = None) -> None:

        model = models.RoleTable(data=sorted(query.policy.roles()))

        super().__init__(title, query, attrname, model, enable_equal=enable_equal,
                         enable_subset=enable_subset, parent=parent)

        self.criteria_any.setToolTip("Any selected role will match.")
        self.criteria_any.setWhatsThis("<b>Any selected role will match.</b>")


class RoleName(NameWidget):

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
    widget = RoleName("Test Role", q, "source", parent=mw)
    widget.setToolTip("test tooltip")
    widget.setWhatsThis("test whats this")
    mw.setCentralWidget(widget)
    mw.resize(widget.size())
    whatsthis = QtWidgets.QWhatsThis.createAction(mw)
    mw.menuBar().addAction(whatsthis)  # type: ignore[union-attr]
    mw.setStatusBar(QtWidgets.QStatusBar(mw))
    mw.show()
    sys.exit(app.exec())
