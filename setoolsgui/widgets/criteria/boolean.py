# SPDX-License-Identifier: LGPL-2.1-only

from PyQt6 import QtWidgets
import setools

from .. import models
from .combobox import ComboBoxWidget
from .list import ListWidget
from .name import NameWidget

# Regex for exact matches to types/attrs
VALIDATE_EXACT = r"[A-Za-z0-9._-]*"

__all__ = ("BooleanList", "BooleanName", "BooleanState")


class BooleanList(ListWidget):

    """A widget providing a QListView widget for selecting zero or more Booleans."""

    def __init__(self, title: str, query, attrname: str, enable_equal: bool = True,
                 parent: QtWidgets.QWidget | None = None) -> None:

        model = models.BooleanTable(data=sorted(query.policy.bools()))

        super().__init__(title, query, attrname, model, enable_equal=enable_equal, parent=parent)

        self.criteria_any.setToolTip("Any selected Boolean will match.")
        self.criteria_any.setWhatsThis("<b>Any selected Boolean will match.</b>")

        if enable_equal:
            self.criteria_equal.setToolTip("The selected Booleans must exactly match.")
            self.criteria_equal.setWhatsThis("<b>The selected Booleans must exactly match.</b>")


class BooleanName(NameWidget):

    """
    Widget providing a QLineEdit for the user to enter a Boolean name, with
    the criteria saved to the attributes of the specified query.
    """

    def __init__(self, title: str, query, attrname: str,
                 parent: QtWidgets.QWidget | None = None,
                 enable_regex: bool = True, required: bool = False):

        completion: list[str] = sorted(b.name for b in query.policy.bools())

        super().__init__(title, query, attrname, completion, VALIDATE_EXACT,
                         enable_regex=enable_regex, required=required, parent=parent)


class BooleanState(ComboBoxWidget):

    """Criteria selection widget presenting possible Boolean states."""

    def __init__(self, title: str, query: setools.PolicyQuery, attrname: str, /, *,
                 enable_any: bool = True, parent: QtWidgets.QWidget | None = None) -> None:

        super().__init__(title, query, attrname, enable_any=enable_any, parent=parent)

        self.criteria.addItem("False", False)
        self.criteria.addItem("True", True)


if __name__ == '__main__':
    import sys
    import logging
    import warnings
    import setools

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
    widget1 = BooleanList("Test Booleans list", q1, "boolean", parent=window)
    widget2 = BooleanName("Test Booleans linedit", q2, "name", parent=window)
    widget3 = BooleanState("Test Booleans State", q2, "default", enable_any=True, parent=window)
    layout.addWidget(widget1)
    layout.addWidget(widget2)
    layout.addWidget(widget3)
    window.setToolTip("test tooltip")
    window.setWhatsThis("test whats this")
    mw.setCentralWidget(window)
    mw.resize(window.size())
    whatsthis = QtWidgets.QWhatsThis.createAction(mw)
    mw.menuBar().addAction(whatsthis)  # type: ignore[union-attr]
    mw.show()
    rc = app.exec()
    sys.exit(rc)
