# SPDX-License-Identifier: LGPL-2.1-only

from contextlib import suppress
from typing import TYPE_CHECKING

from PyQt5 import QtCore, QtGui, QtWidgets

from .list import ListCriteriaWidget
from .name import NameCriteriaWidget
from ..models.boolean import BooleanList

if TYPE_CHECKING:
    from typing import List, Optional

# Regex for exact matches to types/attrs
VALIDATE_EXACT = r"[A-Za-z0-9._-]*"


class BooleanListCriteriaWidget(ListCriteriaWidget):

    """A widget providing a QListView widget for selecting zero or more Booleans."""

    def __init__(self, title: str, query, attrname: str, enable_equal: bool = True,
                 parent: "Optional[QtWidgets.QWidget]" = None) -> None:

        model: BooleanList = BooleanList()
        model.item_list = sorted(query.policy.bools())

        super().__init__(title, query, attrname, model, enable_equal=enable_equal, parent=parent)

        self.criteria_any.setToolTip("Any selected Boolean will match.")
        self.criteria_any.setWhatsThis("<b>Any selected Boolean will match.</b>")

        if enable_equal:
            self.criteria_equal.setToolTip("The selected Booleans must exactly match.")
            self.criteria_equal.setWhatsThis("<b>The selected Booleans must exactly match.</b>")


class BooleanNameCriteriaWidget(NameCriteriaWidget):

    """
    Widget providing a QLineEdit for the user to enter a Boolean name, with
    the criteria saved to the attributes of the specified query.
    """

    def __init__(self, title: str, query, attrname: str,
                 parent: "Optional[QtWidgets.QWidget]" = None,
                 enable_regex: bool = True):

        completion: "List[str]" = sorted(b.name for b in query.policy.bools())

        super().__init__(title, query, attrname, completion, VALIDATE_EXACT,
                         enable_regex=enable_regex, parent=parent)


if __name__ == '__main__':
    import sys
    import logging
    import warnings
    import setools
    import pprint

    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s|%(levelname)s|%(name)s|%(message)s')
    warnings.simplefilter("default")

    p = setools.SELinuxPolicy()
    q1 = setools.TERuleQuery(p)
    q2 = setools.BoolQuery(p)

    app = QtWidgets.QApplication(sys.argv)
    mw = QtWidgets.QMainWindow()
    window = QtWidgets.QWidget(mw)
    layout = QtWidgets.QHBoxLayout(window)
    widget1 = BooleanListCriteriaWidget("Test Booleans list", q1, "boolean", window)
    widget2 = BooleanNameCriteriaWidget("Test Booleans linedit", q2, "name", window)
    layout.addWidget(widget1)
    layout.addWidget(widget2)
    window.setToolTip("test tooltip")
    window.setWhatsThis("test whats this")
    mw.setCentralWidget(window)
    mw.resize(window.size())
    whatsthis = QtWidgets.QWhatsThis.createAction(mw)
    mw.menuBar().addAction(whatsthis)
    mw.show()
    rc = app.exec_()
    print("Query settings:")
    pprint.pprint(q1.boolean)
    sys.exit(rc)
